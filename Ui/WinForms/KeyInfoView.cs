using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using dlech.SshAgentLib;
using System.Security;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;


#if !__MonoCS__
using Microsoft.WindowsAPICodePack.Dialogs;
using Microsoft.WindowsAPICodePack.Dialogs.Controls;
#endif

namespace dlech.SshAgentLib.WinForms
{
  public partial class KeyInfoView : UserControl
  {
#if !__MonoCS__
    private const string cConfirmConstraintCheckBox = "ConfirmConstraintCheckBox";
    private const string cLifetimeConstraintCheckBox = "LifetimeConstraintCheckBox";
    private const string cLifetimeConstraintTextBox = "LifetimeConstraintTextBox";
#endif
    private const int cDragDropKeyStateCtrl = 8;

    private IAgent mAgent;
    private BindingList<KeyWrapper> mKeyCollection;
    private PasswordDialog mPasswordDialog;
    private bool mSelectionChangedBroken;
#if !__MonoCS__
    private CommonOpenFileDialog mWin7OpenFileDialog;
#endif

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

    public KeyInfoView()
    {
      // workaround for mono bug
      try
      {
        var monoRuntimeType = Type.GetType ("Mono.Runtime");
        if (monoRuntimeType != null)
        {
          var getDisplayNameMethod = monoRuntimeType.GetMethod("GetDisplayName",
                                     BindingFlags.NonPublic | BindingFlags.Static);
          var displayName = getDisplayNameMethod.Invoke (null, null) as string;
          var versionRegex = new Regex(@"\d+\.\d+\.\d+\.\d*");
          var match = versionRegex.Match(displayName);
          var version = match.Value;
          mSelectionChangedBroken = Version.Parse (version) < Version.Parse ("2.11.2");
        }
      }
      catch (Exception ex)
      {
        Debug.Fail (ex.ToString());
      }


      InitializeComponent();
#if !__MonoCS__
      if (CommonOpenFileDialog.IsPlatformSupported)
      {
        mWin7OpenFileDialog = new CommonOpenFileDialog();
        mWin7OpenFileDialog.Multiselect = true;
        mWin7OpenFileDialog.EnsureFileExists = true;

        var confirmConstraintCheckBox =
          new CommonFileDialogCheckBox(cConfirmConstraintCheckBox,
          "Require user confirmation");
        var lifetimeConstraintTextBox =
          new CommonFileDialogTextBox(cLifetimeConstraintTextBox, string.Empty);
        lifetimeConstraintTextBox.Visible = false;
        var lifetimeConstraintCheckBox =
          new CommonFileDialogCheckBox(cLifetimeConstraintCheckBox,
          "Set lifetime (in seconds)");
        lifetimeConstraintCheckBox.CheckedChanged +=
          delegate(object aSender, EventArgs aEventArgs)
          {
            lifetimeConstraintTextBox.Visible =
              lifetimeConstraintCheckBox.IsChecked;
          };

        var confirmConstraintGroupBox = new CommonFileDialogGroupBox();
        var lifetimeConstraintGroupBox = new CommonFileDialogGroupBox();

        confirmConstraintGroupBox.Items.Add(confirmConstraintCheckBox);
        lifetimeConstraintGroupBox.Items.Add(lifetimeConstraintCheckBox);
        lifetimeConstraintGroupBox.Items.Add(lifetimeConstraintTextBox);

        mWin7OpenFileDialog.Controls.Add(confirmConstraintGroupBox);
        mWin7OpenFileDialog.Controls.Add(lifetimeConstraintGroupBox);

        var filter = new CommonFileDialogFilter(
          Strings.filterPuttyPrivateKeyFiles, "*.ppk");
        mWin7OpenFileDialog.Filters.Add(filter);
        filter = new CommonFileDialogFilter(Strings.filterAllFiles, "*.*");
        mWin7OpenFileDialog.Filters.Add(filter);

        mWin7OpenFileDialog.FileOk += openFileDialog_FileOk;
      }
      //mWin7OpenFileDialog = null;
#endif
    }

    public void SetAgent(IAgent aAgent)
    {
      // detach existing agent
      if (mAgent != null)
      {
        if (mAgent is Agent)
        {
          var agent = mAgent as Agent;
          agent.KeyListChanged -= AgentKeyListChangeHandler;
          agent.Locked -= AgentLockHandler;
        }
      }

      mAgent = aAgent;

      if (mAgent is Agent)
      {
        var agent = mAgent as Agent;
        confirmDataGridViewCheckBoxColumn.Visible = true;
        lifetimeDataGridViewCheckBoxColumn.Visible = true;
        agent.KeyListChanged += AgentKeyListChangeHandler;
        agent.Locked += AgentLockHandler;
        buttonTableLayoutPanel.Controls.Remove(refreshButton);
        buttonTableLayoutPanel.ColumnCount = 5;
      }
      else
      {
        confirmDataGridViewCheckBoxColumn.Visible = false;
        lifetimeDataGridViewCheckBoxColumn.Visible = false;
        buttonTableLayoutPanel.ColumnCount = 6;
        buttonTableLayoutPanel.Controls.Add(refreshButton, 5, 0);
      }
      ReloadKeyListView();
    }

    public void ShowFileOpenDialog()
    {
      string[] fileNames;
      List<Agent.KeyConstraint> constraints = new List<Agent.KeyConstraint>();
#if !__MonoCS__
      if (mWin7OpenFileDialog != null)
      {
        var result = mWin7OpenFileDialog.ShowDialog();
        if (result != CommonFileDialogResult.Ok)
        {
          return;
        }
        var confirmConstraintCheckBox =
          mWin7OpenFileDialog.Controls[cConfirmConstraintCheckBox] as
          CommonFileDialogCheckBox;
        if (confirmConstraintCheckBox.IsChecked)
        {
          var constraint = new Agent.KeyConstraint();
          constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
          constraints.Add(constraint);
        }
        var lifetimeConstraintCheckBox =
          mWin7OpenFileDialog.Controls[cLifetimeConstraintCheckBox] as
          CommonFileDialogCheckBox;
        var lifetimeConstraintTextBox =
          mWin7OpenFileDialog.Controls[cLifetimeConstraintTextBox] as
          CommonFileDialogTextBox;
        if (lifetimeConstraintCheckBox.IsChecked)
        {
          // error checking for parse done in fileOK event handler
          uint lifetime = uint.Parse(lifetimeConstraintTextBox.Text);
          var constraint = new Agent.KeyConstraint();
          constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
          constraint.Data = lifetime;
          constraints.Add(constraint);
        }
        fileNames = mWin7OpenFileDialog.FileNames.ToArray();
      }
      else
      {
#endif
        var result = openFileDialog.ShowDialog();
        if (result != DialogResult.OK)
        {
          return;
        }
        fileNames = openFileDialog.FileNames;
#if !__MonoCS__
      }
#endif
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
      removeAllbutton.Enabled = dataGridView.Rows.Count > 0 &&
        !isLocked;
    }

    private void AgentLockHandler(object aSender, Agent.LockEventArgs aArgs)
    {
      if (InvokeRequired)
      {
        Invoke((MethodInvoker)delegate()
        {
          AgentLockHandler(aSender, aArgs);
        });
        return;
      }

      UpdateVisibility();
      UpdateButtonStates();
    }

    private void AgentKeyListChangeHandler(object aSender,
      Agent.KeyListChangeEventArgs aArgs)
    {
      if (IsDisposed)
      {
        return;
      }
      if (InvokeRequired)
      {
        Invoke((MethodInvoker)delegate()
          {
            AgentKeyListChangeHandler(aSender, aArgs);
          });
        return;
      }
      switch (aArgs.Action)
      {
        case Agent.KeyListChangeEventAction.Add:
          mKeyCollection.Add(new KeyWrapper(aArgs.Key));
          UpdateVisibility();
          break;
        case Agent.KeyListChangeEventAction.Remove:
          var matchFingerprint = aArgs.Key.GetMD5Fingerprint().ToHexString();
          var matches = mKeyCollection.Where(k =>
            k.Fingerprint == matchFingerprint).ToList();
          foreach (var key in matches)
          {
            mKeyCollection.Remove(key);
          }
          UpdateVisibility();
          break;
      }
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
        e.Effect = DragDropEffects.Move;
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
          if ((e.KeyState & cDragDropKeyStateCtrl) == cDragDropKeyStateCtrl)
          {
            var constraint = new Agent.KeyConstraint();
            constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
            constraints.Add(constraint);
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

    private void removeButton_Click(object sender, EventArgs e)
    {
      foreach (DataGridViewRow row in dataGridView.SelectedRows)
      {
        var keyWrapper = row.DataBoundItem as KeyWrapper;
        var key = keyWrapper.GetKey();
        try
        {
          mAgent.RemoveKey(key);
        } catch (Exception)
        {
          MessageBox.Show(String.Format(Strings.errRemoveFailed,
            key.GetMD5Fingerprint().ToHexString()), Util.AssemblyTitle,
            MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
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

    private void openFileDialog_FileOk(object sender, CancelEventArgs e)
    {
#if !__MonoCS__
      if (mWin7OpenFileDialog != null)
      {
        var lifetimeConstraintCheckBox =
          mWin7OpenFileDialog.Controls[cLifetimeConstraintCheckBox] as
          CommonFileDialogCheckBox;
        var lifetimeConstraintTextBox =
          mWin7OpenFileDialog.Controls[cLifetimeConstraintTextBox] as
          CommonFileDialogTextBox;
        if (lifetimeConstraintCheckBox.IsChecked)
        {
          uint lifetime;
          var success = uint.TryParse(lifetimeConstraintTextBox.Text, out lifetime);
          if (!success)
          {
            MessageBox.Show("Invalid lifetime", Util.AssemblyTitle,
              MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            e.Cancel = true;
            return;
          }
        }
      }
#endif
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

  }
}
