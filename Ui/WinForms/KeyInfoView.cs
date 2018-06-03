//
// KeyInfoView.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013-2014,2016-2017 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using FileDialogExtenders;
using Microsoft.WindowsAPICodePack.Dialogs;
using Microsoft.WindowsAPICodePack.Dialogs.Controls;

namespace dlech.SshAgentLib.WinForms
{
  public partial class KeyInfoView : UserControl
  {
    private const string cConfirmConstraintCheckBox = "ConfirmConstraintCheckBox";
    private const string cLifetimeConstraintCheckBox = "LifetimeConstraintCheckBox";
    private const string cLifetimeConstraintTextBox = "LifetimeConstraintTextBox";
    private const int cDragDropKeyStateCtrl = 8;

    private IAgent mAgent;
    private BindingList<KeyWrapper> mKeyCollection;
    private PasswordDialog mPasswordDialog;
    private bool mSelectionChangedBroken;
    private int mButtonLayoutInitialColumnCount;
    private Dictionary<OpenFileDialog, XPOpenFileDialog> mOpenFileDialogMap;

    public ContextMenuStrip AddButtonSplitMenu
    {
      get
      {
        return addKeyButton.SplitMenuStrip;
      }
      set
      {
        addKeyButton.SplitMenuStrip = value;
        addKeyButton.ShowSplit = (value != null);
      }
    }

    private PasswordDialog PasswordDialog
    {
      get
      {
        if (mPasswordDialog == null)
        {
          mPasswordDialog = new PasswordDialog();
        }
        return mPasswordDialog;
      }
    }

    public event EventHandler AddFromFileHelpRequested;

    public KeyInfoView()
    {
      mOpenFileDialogMap = new Dictionary<OpenFileDialog, XPOpenFileDialog>();
      var monoRuntimeType = Type.GetType ("Mono.Runtime");
      if (monoRuntimeType != null) {
        // workaround for mono bug
        try {
          var getDisplayNameMethod = monoRuntimeType.GetMethod ("GetDisplayName",
                                     BindingFlags.NonPublic | BindingFlags.Static);
          var displayName = getDisplayNameMethod.Invoke (null, null) as string;
          var versionRegex = new Regex (@"\d+\.\d+\.\d+(\.\d+)?");
          var match = versionRegex.Match (displayName);
          var version = match.Value;
          mSelectionChangedBroken = Version.Parse (version) < Version.Parse ("2.11.2");
        } catch (Exception ex) {
          Debug.Fail (ex.ToString ());
        }
      }

      InitializeComponent();
      mButtonLayoutInitialColumnCount = buttonTableLayoutPanel.ColumnCount;
      if (monoRuntimeType != null) {
        buttonTableLayoutPanel.Margin = new Padding ();
      }
    }

    public void SetAgent(IAgent aAgent)
    {
      // detach existing agent
      if (mAgent != null)
      {
        if (mAgent is Agent)
        {
          var agent = mAgent as Agent;
          agent.KeyAdded -= AgentKeyAddedHandler;
          agent.KeyRemoved -= AgentKeyRemovedHandler;
          agent.Locked -= AgentLockHandler;
        }
      }

      buttonTableLayoutPanel.ColumnCount = mButtonLayoutInitialColumnCount;
      buttonTableLayoutPanel.Controls.Clear();

      mAgent = aAgent;
      if (mAgent is Agent)
      {
        var agent = mAgent as Agent;
        confirmDataGridViewCheckBoxColumn.Visible = true;
        lifetimeDataGridViewCheckBoxColumn.Visible = true;
        sourceDataGridViewTextBoxColumn.Visible = true;
        agent.KeyAdded += AgentKeyAddedHandler;
        agent.KeyRemoved += AgentKeyRemovedHandler;
        agent.Locked += AgentLockHandler;
        buttonTableLayoutPanel.ColumnCount -= 1;

        buttonTableLayoutPanel.Controls.Add(lockButton, 0, 0);
        buttonTableLayoutPanel.Controls.Add(unlockButton, 1, 0);
        buttonTableLayoutPanel.Controls.Add(addKeyButton, 2, 0);
        buttonTableLayoutPanel.Controls.Add(removeKeyButton, 3, 0);
        buttonTableLayoutPanel.Controls.Add(removeAllButton, 4, 0);
      }
      else
      {
        // hide lock/unlock buttons if using Pageant since they are not supported
        if (mAgent is PageantClient) {
          buttonTableLayoutPanel.ColumnCount -= 2;
        } else {
          buttonTableLayoutPanel.Controls.Add(lockButton, 0, 0);
          buttonTableLayoutPanel.Controls.Add(unlockButton, 1, 0);
        }
        var colCount = buttonTableLayoutPanel.ColumnCount;
        buttonTableLayoutPanel.Controls.Add(addKeyButton, colCount - 4, 0);
        buttonTableLayoutPanel.Controls.Add(removeKeyButton, colCount - 3, 0);
        buttonTableLayoutPanel.Controls.Add(removeAllButton, colCount - 2, 0);
        buttonTableLayoutPanel.Controls.Add(refreshButton, colCount - 1, 0);

        confirmDataGridViewCheckBoxColumn.Visible = false;
        lifetimeDataGridViewCheckBoxColumn.Visible = false;
        sourceDataGridViewTextBoxColumn.Visible = false;
      }

      for (int i = 0; i < buttonTableLayoutPanel.ColumnCount; i++) {
        if (Type.GetType ("Mono.Runtime") == null) {
          buttonTableLayoutPanel.ColumnStyles [i] =
            new ColumnStyle (SizeType.Percent, 100F / buttonTableLayoutPanel.ColumnCount);
        } else {
          // Mono doens't do automatic layouts correctly, so use fixed width
          buttonTableLayoutPanel.ColumnStyles [i] =
            new ColumnStyle (SizeType.Absolute,
              buttonTableLayoutPanel.Width / buttonTableLayoutPanel.ColumnCount);
        }
      }

      ReloadKeyListView();
    }

    public void ShowFileOpenDialog()
    {
      string[] fileNames;
      List<Agent.KeyConstraint> constraints = new List<Agent.KeyConstraint>();
      if (mAgent is PageantClient) {
        // Client Mode with Pageant - Show standard file dialog since we don't
        // need / can't use constraints

        using (var openFileDialog = new OpenFileDialog()) {
          openFileDialog.Multiselect = true;
          openFileDialog.Filter = string.Join ("|",
            Strings.filterPuttyPrivateKeyFiles, "*.ppk",
            Strings.filterAllFiles, "*.*");

          var result = openFileDialog.ShowDialog ();
          if (result != DialogResult.OK) {
            return;
          }
          fileNames = openFileDialog.FileNames;
        }
      } else if (CommonOpenFileDialog.IsPlatformSupported) {
        // Windows Vista/7/8 has new style file open dialog that can be extended
        // using the Windows API via the WindowsAPICodepack library

        var win7OpenFileDialog = new CommonOpenFileDialog ();
        win7OpenFileDialog.Multiselect = true;
        win7OpenFileDialog.EnsureFileExists = true;

        var confirmConstraintCheckBox =
          new CommonFileDialogCheckBox (cConfirmConstraintCheckBox,
          "Require user confirmation");
        var lifetimeConstraintTextBox =
          new CommonFileDialogTextBox (cLifetimeConstraintTextBox, string.Empty);
        lifetimeConstraintTextBox.Visible = false;
        var lifetimeConstraintCheckBox =
          new CommonFileDialogCheckBox (cLifetimeConstraintCheckBox,
          "Set lifetime (in seconds)");
        lifetimeConstraintCheckBox.CheckedChanged += (s, e) => {
          lifetimeConstraintTextBox.Visible =
              lifetimeConstraintCheckBox.IsChecked;
        };

        var confirmConstraintGroupBox = new CommonFileDialogGroupBox ();
        var lifetimeConstraintGroupBox = new CommonFileDialogGroupBox ();

        confirmConstraintGroupBox.Items.Add (confirmConstraintCheckBox);
        lifetimeConstraintGroupBox.Items.Add (lifetimeConstraintCheckBox);
        lifetimeConstraintGroupBox.Items.Add (lifetimeConstraintTextBox);

        win7OpenFileDialog.Controls.Add (confirmConstraintGroupBox);
        win7OpenFileDialog.Controls.Add (lifetimeConstraintGroupBox);

        var filter = new CommonFileDialogFilter (
          Strings.filterPuttyPrivateKeyFiles, "*.ppk");
        win7OpenFileDialog.Filters.Add (filter);
        filter = new CommonFileDialogFilter (Strings.filterAllFiles, "*.*");
        win7OpenFileDialog.Filters.Add (filter);

        win7OpenFileDialog.FileOk += win7OpenFileDialog_FileOk;

        /* add help listeners to win7OpenFileDialog */

        // declare variables here so that the GC does not eat them.
        WndProcDelegate newWndProc, oldWndProc = null;
        win7OpenFileDialog.DialogOpening += (sender, e) =>
        {
          var hwnd = win7OpenFileDialog.GetWindowHandle();

          // hook into WndProc to catch WM_HELP, i.e. user pressed F1
          newWndProc = (hWnd, msg, wParam, lParam) =>
          {
            const short shellHelpCommand = 0x7091;

            var win32Msg = (Win32Types.Msg)msg;
            switch (win32Msg) {
              case Win32Types.Msg.WM_HELP:
                var helpInfo = (HELPINFO)Marshal.PtrToStructure(lParam, typeof(HELPINFO));
                // Ignore if we are on an unknown control or control 100.
                // These are the windows shell control. The help command is
                // issued by these controls so by not ignoring, we would call
                // the help method twice.
                if (helpInfo.iCtrlId != 0 && helpInfo.iCtrlId != 100)
                  OnAddFromFileHelpRequested(win7OpenFileDialog, EventArgs.Empty);
                return (IntPtr)1; // TRUE
              case Win32Types.Msg.WM_COMMAND:
                var wParamBytes = BitConverter.GetBytes(wParam.ToInt32());
                var highWord = BitConverter.ToInt16(wParamBytes, 0);
                var lowWord = BitConverter.ToInt16(wParamBytes, 2);
                if (lowWord == 0 && highWord == shellHelpCommand) {
                  OnAddFromFileHelpRequested(win7OpenFileDialog, EventArgs.Empty);
                  return (IntPtr)0;
                }
                break;
            }
            return CallWindowProc(oldWndProc, hwnd, msg, wParam, lParam);
          };
          var newWndProcPtr = Marshal.GetFunctionPointerForDelegate(newWndProc);
          var oldWndProcPtr = SetWindowLongPtr(hwnd, WindowLongFlags.GWL_WNDPROC, newWndProcPtr);
          oldWndProc = (WndProcDelegate)
              Marshal.GetDelegateForFunctionPointer(oldWndProcPtr, typeof(WndProcDelegate));
        };

        var result = win7OpenFileDialog.ShowDialog ();
        if (result != CommonFileDialogResult.Ok) {
          return;
        }
        if (confirmConstraintCheckBox.IsChecked) {
          var constraint = new Agent.KeyConstraint ();
          constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
          constraints.Add (constraint);
        }
        if (lifetimeConstraintCheckBox.IsChecked) {
          // error checking for parse done in fileOK event handler
          uint lifetime = uint.Parse (lifetimeConstraintTextBox.Text);
          var constraint = new Agent.KeyConstraint ();
          constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
          constraint.Data = lifetime;
          constraints.Add (constraint);
        }
        fileNames = win7OpenFileDialog.FileNames.ToArray ();
      } else {
        using (var openFileDialog = new OpenFileDialog())
        {
          openFileDialog.Multiselect = true;
          openFileDialog.Filter = string.Join ("|",
            Strings.filterPuttyPrivateKeyFiles, "*.ppk",
             Strings.filterAllFiles, "*.*");

          openFileDialog.FileOk += xpOpenFileDialog_FileOk;
          
          // Windows XP uses old style file open dialog that can be extended
          // using the Windows API via FileDlgExtenders library
          XPOpenFileDialog xpOpenFileDialog = null;
          if (Type.GetType("Mono.Runtime") == null) {
            xpOpenFileDialog = new XPOpenFileDialog ();
            xpOpenFileDialog.FileDlgStartLocation = AddonWindowLocation.Bottom;
            mOpenFileDialogMap.Add (openFileDialog, xpOpenFileDialog);
          }

          openFileDialog.HelpRequest += OnAddFromFileHelpRequested;
          // TODO: technically, a listener could be added after this
          openFileDialog.ShowHelp = AddFromFileHelpRequested != null;

          var result = xpOpenFileDialog == null ?
            openFileDialog.ShowDialog() :
            openFileDialog.ShowDialog(xpOpenFileDialog, null);
          if (result != DialogResult.OK)
            return;

          if (xpOpenFileDialog == null) {
            // If dialog could not be extended, then we add constraints by holding
            // down the control key when clicking the Open button.
            if (Control.ModifierKeys.HasFlag(Keys.Control)) {
              var constraintDialog = new ConstraintsInputDialog ();
              constraintDialog.ShowDialog ();
              if (constraintDialog.DialogResult == DialogResult.OK) {
                if (constraintDialog.ConfirmConstraintChecked) {
                  constraints.AddConfirmConstraint ();
                }
                if (constraintDialog.LifetimeConstraintChecked) {
                  constraints.AddLifetimeConstraint (constraintDialog.LifetimeDuration);
                }
              }
            }
          } else {
            mOpenFileDialogMap.Remove (openFileDialog);

            if (xpOpenFileDialog.UseConfirmConstraintChecked) {
              constraints.AddConfirmConstraint ();
            }
            if (xpOpenFileDialog.UseLifetimeConstraintChecked) {
              constraints.AddLifetimeConstraint
                (xpOpenFileDialog.LifetimeConstraintDuration);
            }
          }
          fileNames = openFileDialog.FileNames;
        }
      }
      UseWaitCursor = true;
      mAgent.AddKeysFromFiles(fileNames, constraints);
      if (!(mAgent is Agent))
      {
        ReloadKeyListView();
      }
      UseWaitCursor = false;
    }

    public void ReloadKeyListView()
    {
      // workaround for bug where first column (0) is always set
      // to Visible = true when data changes
      var columnZeroVisible = dataGridView.Columns[0].Visible;

      mKeyCollection = new BindingList<KeyWrapper>();
      dataGridView.DataSource = mKeyCollection;
      try
      {
        foreach (var key in mAgent.GetAllKeys())
        {
          mKeyCollection.Add(new KeyWrapper(key));
        }
        // TODO show different error messages for specific exceptions
        // should also do something besides MessageBox so that this control
        // can be integrated into other applications
      } catch (Exception)
      {
        MessageBox.Show(Strings.errListKeysFailed, Util.AssemblyTitle,
          MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
      dataGridView.Columns[0].Visible = columnZeroVisible;
      UpdateVisibility();
      UpdateButtonStates();
    }

    void OnAddFromFileHelpRequested(object sender, EventArgs e)
    {
      if (AddFromFileHelpRequested != null)
        AddFromFileHelpRequested(sender, e);
    }

    private void UpdateVisibility()
    {
      var agent = mAgent as Agent;
      dataGridView.Visible = dataGridView.RowCount > 0 &&
        (agent == null || !agent.IsLocked);
      if (agent != null && agent.IsLocked)
      {
        messageLabel.Text = Strings.keyInfoViewLocked;
      }
      else if (agent != null)
      {
        messageLabel.Text = Strings.keyInfoViewNoKeys;
      }
      else
      {
        messageLabel.Text = Strings.keyInfoViewClickRefresh;
      }
    }

    private void UpdateButtonStates()
    {
      var isLocked = false;
      var agent = mAgent as Agent;
      if (agent != null)
      {
        isLocked = agent.IsLocked;
      }
      lockButton.Enabled = !isLocked;
      unlockButton.Enabled = agent == null || isLocked;
      addKeyButton.Enabled = !isLocked;
      removeKeyButton.Enabled = mSelectionChangedBroken ||
        (dataGridView.SelectedRows.Count > 0 && !isLocked);
      removeAllButton.Enabled = dataGridView.Rows.Count > 0 &&
        !isLocked;
    }

    private void AgentLockHandler(object sender, Agent.LockEventArgs e)
    {
      if (InvokeRequired)
      {
        Invoke((MethodInvoker)delegate()
        {
          AgentLockHandler(sender, e);
        });
        return;
      }

      UpdateVisibility();
      UpdateButtonStates();
    }

    private void AgentKeyAddedHandler(object sender, SshKeyEventArgs e)
    {
      if (IsDisposed) {
        return;
      }
      if (InvokeRequired) {
        Invoke((MethodInvoker)delegate() {
            AgentKeyAddedHandler(sender, e);
        });
        return;
      }
      mKeyCollection.Add(new KeyWrapper(e.Key));
      UpdateVisibility();
      UpdateButtonStates();
    }

    private void AgentKeyRemovedHandler(object sender, SshKeyEventArgs e)
    {
      if (IsDisposed) {
        return;
      }
      if (InvokeRequired) {
        Invoke((MethodInvoker)delegate() {
          AgentKeyRemovedHandler(sender, e);
        });
        return;
      }
      var matchFingerprint = e.Key.GetMD5Fingerprint().ToHexString();
      var matches = mKeyCollection.Where(k =>
        k.Fingerprint == matchFingerprint).ToList();
      foreach (var key in matches) {
        mKeyCollection.Remove(key);
      }
      UpdateVisibility();
      UpdateButtonStates();
    }

    // SelectionChanged event is broken on mono <= 2.11.1
    private void dataGridView_SelectionChanged(object sender, EventArgs e)
    {
      UpdateButtonStates();
    }

    private void dataGridView_DragEnter(object sender, DragEventArgs e)
    {
      if ((mAgent != null) && e.Data.GetDataPresent(DataFormats.FileDrop))
      {
        e.Effect = DragDropEffects.Copy;
      }
      else
      {
        e.Effect = DragDropEffects.None;
      }
    }

    private void dataGridView_DragDrop(object sender, DragEventArgs e)
    {
      if (e.Data.GetDataPresent(DataFormats.FileDrop))
      {
        var fileNames = e.Data.GetData(DataFormats.FileDrop) as string[];
        if (mAgent != null)
        {
          UseWaitCursor = true;
          var constraints = new List<Agent.KeyConstraint>();
          // MONO WORKAROUND - mono does not provide e.KeyState information
          // it is always 0. However, when pressing the Control key (at least
          // in Gnome), e.AllowedEffect is limited to just Copy, so we can use
          // it to detect that the control key has been pressed
          if ((e.KeyState & cDragDropKeyStateCtrl) == cDragDropKeyStateCtrl ||
              e.AllowedEffect == DragDropEffects.Copy)
          {
            var dialog = new ConstraintsInputDialog();
            dialog.ShowDialog();
            if (dialog.DialogResult == DialogResult.OK) {
              if (dialog.ConfirmConstraintChecked) {
                constraints.AddConfirmConstraint();
              }
              if (dialog.LifetimeConstraintChecked) {
                constraints.AddLifetimeConstraint(dialog.LifetimeDuration);
              }
            }
          }
          mAgent.AddKeysFromFiles(fileNames, constraints);
          if (!(mAgent is Agent))
          {
            // if this is client, then reload key list from remote agent
            SetAgent(mAgent);
          }
          UseWaitCursor = false;
        }
      }
    }

    private void addKeyButton_Click(object sender, EventArgs e)
    {
      if (AddButtonSplitMenu == null)
      {
        ShowFileOpenDialog();
      }
      else
      {
        addKeyButton.ShowContextMenuStrip();
      }

    }

    private void removeRow(DataGridViewRow row)
    {
      var keyWrapper = row.DataBoundItem as KeyWrapper;
      var key = keyWrapper.GetKey();
      try {
        mAgent.RemoveKey(key);
      }
      catch (Exception) {
        MessageBox.Show(String.Format(Strings.errRemoveFailed,
          key.GetMD5Fingerprint().ToHexString()), Util.AssemblyTitle,
          MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void removeButton_Click(object sender, EventArgs e)
    {
      foreach (DataGridViewRow row in dataGridView.SelectedRows)
      {
        removeRow(row);
      }
      if (!(mAgent is Agent))
      {
        ReloadKeyListView();
      }
    }

    private void lockButton_Click(object sender, EventArgs e)
    {
      var result = PasswordDialog.ShowDialog();
      if (result != DialogResult.OK)
      {
        return;
      }
      if (PasswordDialog.SecureEdit.TextLength == 0)
      {
        result = MessageBox.Show(Strings.keyManagerAreYouSureLockPassphraseEmpty,
          Util.AssemblyTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Question,
          MessageBoxDefaultButton.Button2);
        if (result != DialogResult.Yes)
        {
          return;
        }
      }
      try
      {
        mAgent.Lock(PasswordDialog.SecureEdit.ToUtf8());
      } catch (AgentLockedException)
      {
        Debug.Fail("Button state should prevent this");
        MessageBox.Show("Agent is already locked", Util.AssemblyTitle,
          MessageBoxButtons.OK, MessageBoxIcon.Error);
        UpdateButtonStates();
      } catch (AgentFailureException)
      {
        MessageBox.Show("Locking Failed.\n" +
            "Possible Causes:\n" +
            "- Agent is already locked.\n" +
            "- Agent does not support locking.",
            Util.AssemblyTitle,
            MessageBoxButtons.OK, MessageBoxIcon.Error);
      } catch (Exception)
      {
        MessageBox.Show(Strings.errLockFailed, Util.AssemblyTitle,
          MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
      if (!(mAgent is Agent))
      {
        ReloadKeyListView();
      }
    }

    private void unlockButton_Click(object sender, EventArgs e)
    {
      var result = PasswordDialog.ShowDialog();
      if (result != DialogResult.OK)
      {
        return;
      }
      try
      {
        mAgent.Unlock(PasswordDialog.SecureEdit.ToUtf8());
      } catch (PassphraseException)
      {
        MessageBox.Show("Incorrect Passphrase", Util.AssemblyTitle,
            MessageBoxButtons.OK, MessageBoxIcon.Error);
      } catch (AgentLockedException)
      {
        Debug.Fail("Button state should prevent this");
        MessageBox.Show("Agent is already unlocked", Util.AssemblyTitle,
            MessageBoxButtons.OK, MessageBoxIcon.Error);
        UpdateButtonStates();
      } catch (AgentFailureException)
      {
        MessageBox.Show("Unlocking Failed.\n" +
            "Possible Causes:\n" +
            "- Passphrase was incorrect.\n" +
            "- Agent is already unlocked.\n" +
            "- Agent does not support locking.",
            Util.AssemblyTitle,
            MessageBoxButtons.OK, MessageBoxIcon.Error);
      } catch (Exception)
      {
        MessageBox.Show(Strings.errUnlockFailed, Util.AssemblyTitle,
          MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
      ReloadKeyListView();
    }

    private void removeAllButton_Click(object sender, EventArgs e)
    {
      mAgent.RemoveAllKeys();
      if (!(mAgent is Agent))
      {
        ReloadKeyListView();
      }
    }

    private void refreshButton_Click(object sender, EventArgs e)
    {
      ReloadKeyListView();
    }

    private void win7OpenFileDialog_FileOk(object sender, CancelEventArgs e)
    {
      var win7OpenFileDialog = sender as CommonOpenFileDialog;
      if (win7OpenFileDialog != null)
      {
        var lifetimeConstraintCheckBox =
          win7OpenFileDialog.Controls[cLifetimeConstraintCheckBox] as
          CommonFileDialogCheckBox;
        var lifetimeConstraintTextBox =
          win7OpenFileDialog.Controls[cLifetimeConstraintTextBox] as
          CommonFileDialogTextBox;
        if (lifetimeConstraintCheckBox.IsChecked)
        {
          uint lifetime;
          var success = uint.TryParse(lifetimeConstraintTextBox.Text, out lifetime);
          if (!success || lifetime == 0)
          {
            MessageBox.Show("Invalid lifetime", Util.AssemblyTitle,
              MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            e.Cancel = true;
            return;
          }
        }
      }
    }

    private void xpOpenFileDialog_FileOk(object sender, CancelEventArgs e)
    {
      var openFileDialog = sender as OpenFileDialog;
      if (openFileDialog != null &&
          mOpenFileDialogMap.ContainsKey(openFileDialog))
      {
        var xpOpenFileDialog = mOpenFileDialogMap[openFileDialog];
        if (xpOpenFileDialog.UseLifetimeConstraintChecked) {
          if (xpOpenFileDialog.LifetimeConstraintDuration == 0) {
            MessageBox.Show("Invalid lifetime", Util.AssemblyTitle,
              MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            e.Cancel = true;
            return;
          }
        }
      }
    }

    private void KeyManagerForm_KeyUp(object sender, KeyEventArgs e)
    {
      if (e.Modifiers == Keys.None && e.KeyData == Keys.F5)
      {
        if (!(mAgent is Agent))
        {
          ReloadKeyListView();
        }
      }
    }

    private void dataGridView_CellPainting(object sender,
                                           DataGridViewCellPaintingEventArgs e)
    {
      // Override the drawing of the checkbox for the confirm and lifetime 
      // constraints. The default rendering looks like you should be able
      // to check the boxes, but they are really read-only.
      if (e.RowIndex >= 0 &&
          (e.ColumnIndex == confirmDataGridViewCheckBoxColumn.Index ||
           e.ColumnIndex == lifetimeDataGridViewCheckBoxColumn.Index))
      {
        
        var backColorBrush = new SolidBrush
          (e.State.HasFlag(DataGridViewElementStates.Selected) ?
           e.CellStyle.SelectionBackColor :
           e.CellStyle.BackColor);

        e.Graphics.FillRectangle(backColorBrush, e.CellBounds);

        var gridBrush = new SolidBrush(this.dataGridView.GridColor);
        var gridLinePen = new Pen(gridBrush);

        e.Graphics.DrawLine(gridLinePen, e.CellBounds.Left,
                            e.CellBounds.Bottom - 1, e.CellBounds.Right - 1,
                            e.CellBounds.Bottom - 1);
        e.Graphics.DrawLine(gridLinePen, e.CellBounds.Right - 1,
                            e.CellBounds.Top, e.CellBounds.Right - 1,
                            e.CellBounds.Bottom);

        var foreColorPen = new Pen
         (e.State.HasFlag(DataGridViewElementStates.Selected) ?
          e.CellStyle.SelectionForeColor :
          e.CellStyle.ForeColor);

        if (e.Value is bool && ((bool)e.Value)) {
          var midX = e.CellBounds.X + e.CellBounds.Width / 2;
          var midY = e.CellBounds.Y + e.CellBounds.Height / 2;
          e.Graphics.DrawImage (Properties.Resources.checkmark, midX - 8, midY - 8, 16, 16);
        }

        e.Handled = true;
      }
    }

    enum WindowLongFlags : int
    {
      GWL_EXSTYLE = -20,
      GWLP_HINSTANCE = -6,
      GWLP_HWNDPARENT = -8,
      GWL_ID = -12,
      GWL_STYLE = -16,
      GWL_USERDATA = -21,
      GWL_WNDPROC = -4,
      DWLP_USER = 0x8,
      DWLP_MSGRESULT = 0x0,
      DWLP_DLGPROC = 0x4
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
      public int X, Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct HELPINFO
    {
      public uint cbSize;
      public int iContextType;
      public int iCtrlId;
      public IntPtr hItemHandle;
      public IntPtr dwContextId;
      public POINT MousePos;
    };

    /// <summary>
    /// Changes an attribute of the specified window. The function also sets the 32-bit (long) value at the specified offset into the extra window memory.
    /// </summary>
    /// <param name="hWnd">A handle to the window and, indirectly, the class to which the window belongs..</param>
    /// <param name="nIndex">The zero-based offset to the value to be set. Valid values are in the range zero through the number of bytes of extra window memory, minus the size of an integer. To set any other value, specify one of the following values: GWL_EXSTYLE, GWL_HINSTANCE, GWL_ID, GWL_STYLE, GWL_USERDATA, GWL_WNDPROC </param>
    /// <param name="dwNewLong">The replacement value.</param>
    /// <returns>If the function succeeds, the return value is the previous value of the specified 32-bit integer.
    /// If the function fails, the return value is zero. To get extended error information, call GetLastError. </returns>
    static IntPtr SetWindowLongPtr(IntPtr hWnd, WindowLongFlags nIndex, IntPtr dwNewLong)
    {
      if (IntPtr.Size == 8)
        return SetWindowLongPtr64(hWnd, nIndex, dwNewLong);
      else
        return new IntPtr(SetWindowLong32(hWnd, nIndex, dwNewLong.ToInt32()));
    }

    [DllImport("user32.dll", EntryPoint = "SetWindowLong")]
    static extern int SetWindowLong32(IntPtr hWnd, WindowLongFlags nIndex, int dwNewLong);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtr")]
    static extern IntPtr SetWindowLongPtr64(IntPtr hWnd, WindowLongFlags nIndex, IntPtr dwNewLong);

    [DllImport("user32.dll")]
    static extern IntPtr CallWindowProc(WndProcDelegate lpPrevWndFunc, IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    private void dataGridView_CellContextMenuStripNeeded(object sender, DataGridViewCellContextMenuStripNeededEventArgs e)
    {
      e.ContextMenuStrip = contextMenuStrip1;
      contextMenuStrip1.Tag = dataGridView.Rows[e.RowIndex];
    }

    private void removeKeyToolStripMenuItem_Click(object sender, EventArgs e)
    {
      var row = contextMenuStrip1.Tag as DataGridViewRow;
      Debug.Assert(row != null);
      removeRow(row);
      if (!(mAgent is Agent)) {
        ReloadKeyListView();
      }
    }

    private void toolStripMenuItemCopyAuthorizedKeys_Click(object sender, EventArgs e)
    {
      var row = contextMenuStrip1.Tag as DataGridViewRow;
      Debug.Assert(row != null);
      var keyWrapper = row.DataBoundItem as KeyWrapper;
      var key = keyWrapper.GetKey();
      Clipboard.SetText(key.GetAuthorizedKeyString());
    }
  }
}
