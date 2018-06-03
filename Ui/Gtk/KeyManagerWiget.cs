//
// KeyManagerWidget.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013 David Lechner
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
using System.Diagnostics;
using System.Linq;
using dlech.SshAgentLib;
using Gtk;

namespace SshAgentLib.GTK
{
  [System.ComponentModel.ToolboxItem(true)]
  public partial class KeyManagerWiget : Gtk.Bin
  {
    private IAgent mAgent;
    private Gtk.NodeStore mKeyCollection;


    public KeyManagerWiget ()
    {
      this.Build ();

      // TODO - extract strings
      mKeyNodeView.AppendColumn ("C", new Gtk.CellRendererToggle(), "active", 0);
      mKeyNodeView.AppendColumn ("L", new Gtk.CellRendererToggle(), "active", 1);
      mKeyNodeView.AppendColumn ("Size", new Gtk.CellRendererText(), "text", 2);
      mKeyNodeView.AppendColumn ("Type", new Gtk.CellRendererText(), "text", 3);
      mKeyNodeView.AppendColumn ("Fingerprint", new Gtk.CellRendererText(), "text", 4);
      mKeyNodeView.AppendColumn ("Comment", new Gtk.CellRendererText(), "text", 5);

      mKeyNodeView.Selection.Mode = SelectionMode.Multiple;
      mKeyNodeView.Selection.Changed += mKeyNodeView_Selection_Changed;
    }

    public void SetAgent(IAgent aAgent)
    {
      // detach existing agent
      if (mAgent != null) {
        if (mAgent is Agent) {
          var agent = mAgent as Agent;
          agent.KeyListChanged -= AgentKeyListChangeHandler;
          agent.Locked -= AgentLockHandler;
        }
      }

      mAgent = aAgent;

      if (mAgent is Agent) {
        var agent = mAgent as Agent;
        mKeyNodeView.Columns[0].Visible = true;
        mKeyNodeView.Columns[1].Visible = true;
        agent.KeyListChanged += AgentKeyListChangeHandler;
        agent.Locked += AgentLockHandler;
        //buttonTableLayoutPanel.Controls.Remove(refreshButton);
        //buttonTableLayoutPanel.ColumnCount = 5;
      } else {
        mKeyNodeView.Columns[0].Visible = false;
        mKeyNodeView.Columns[1].Visible = false;
        //buttonTableLayoutPanel.ColumnCount = 6;
        //buttonTableLayoutPanel.Controls.Add(refreshButton, 5, 0);
      }
      ReloadKeyListView();
    }

    private void ReloadKeyListView()
    {
          
      mKeyCollection = new Gtk.NodeStore(typeof(KeyNode));
      try {
        foreach (var key in mAgent.GetAllKeys()) {
          mKeyCollection.AddNode (new KeyNode(key));
        }
        mKeyNodeView.NodeStore  = mKeyCollection;
        //mKeyNodeView.ShowAll ();
        //mKeyNodeView.ColumnsAutosize ();
        // TODO show different error messages for specific exceptions
        // should also do something besides MessageBox so that this control
        // can be integrated into other applications
      } catch (Exception) {
        // TODO - fix strings
        var messageDialog =
          new Gtk.MessageDialog(null, Gtk.DialogFlags.Modal , 
                                Gtk.MessageType.Error , Gtk.ButtonsType.Close ,
                                "failed"/*Strings.errListKeysFailed*/);
        messageDialog.Run ();
        messageDialog.Destroy ();
      }
      UpdateVisibility();
      UpdateButtonStates();
    }

    private void AgentLockHandler(object sender, Agent.LockEventArgs e)
    {
//      Invoke((MethodInvoker)delegate()
//      {
//        UpdateVisibility();
//        UpdateButtonStates();
//      });
    }

    private void AgentKeyListChangeHandler(object sender, Agent.KeyListChangeEventArgs e)
    {
//      if (IsDisposed) {
//        return;
//      }
      switch (e.Action) {
        case Agent.KeyListChangeEventAction.Add:
          Gtk.Application.Invoke(delegate(object sender1, EventArgs e1)
          {
            mKeyCollection.AddNode(new KeyNode(e.Key));
            UpdateVisibility();
          });
          break;
        case Agent.KeyListChangeEventAction.Remove:
          Gtk.Application.Invoke(delegate(object sender1, EventArgs e1)
          {
            var matchFingerprint = e.Key.GetMD5Fingerprint().ToHexString();

            var matches = mKeyCollection.Cast<KeyNode>()
              .Where(k => k.Fingerprint == matchFingerprint);
            foreach (var keyNode in matches) {
              mKeyCollection.RemoveNode(keyNode);
            }
            UpdateVisibility();
          });
          break;
      }
      
    }

    private void UpdateVisibility()
    {
      var agent = mAgent as Agent;

      mKeyNodeView.Visible = mKeyNodeView.GetNodeCount()  > 0 &&
        (agent == null || !agent.IsLocked);
      if (agent != null && agent.IsLocked) {
        // TODO - fix strings
        label1.Text = "Locked";//Strings.keyInfoViewLocked;
      } else if (agent != null) {
        label1.Text = "No Keys";//Strings.keyInfoViewNoKeys;
      } else {
        label1.Text = "Click 'Refresh' to update";//Strings.keyInfoViewClickRefresh;
      }
    }

    private void UpdateButtonStates()
    {
      var isLocked = false;
      var agent = mAgent as Agent;
      if (agent != null) {
        isLocked = agent.IsLocked;
      }
      mLockButton.Sensitive = !isLocked;
      mUnlockButton.Sensitive = agent == null || isLocked;
      mAddButton.Sensitive = !isLocked;
      mRemoveButton.Sensitive = mKeyNodeView.Selection.CountSelectedRows() > 0 &&
        !isLocked;
      mRemoveAllButton.Sensitive = mKeyNodeView.GetNodeCount () > 0 &&
        !isLocked;
    }

    protected void OnMLockButtonClicked (object sender, EventArgs e)
    {
      try {
        // TODO - get passphrase
        mAgent.Lock (new byte[0]); 
        } catch (AgentLockedException) {
        // TODO - show error message
      } catch (Exception ex) {
        Debug.Fail(ex.ToString ());
      }
      if (!(mAgent is Agent)) {
        ReloadKeyListView ();
      }
    }

    protected void OnMUnlockButtonClicked (object sender, EventArgs e)
    {
     try {
        // TODO - get passphrase
        mAgent.Unlock (new byte[0]); 
        } catch (AgentLockedException) {
        // TODO - show error message
      } catch (Exception ex) {
        Debug.Fail(ex.ToString ());
      }
      if (!(mAgent is Agent)) {
        ReloadKeyListView ();
      }
    }    

    protected void OnMAddButtonClicked (object sender, EventArgs e)
    {
      // TODO - fix strings
      var dialog = new Gtk.FileChooserDialog (
        "Select private key files",
        null,
        FileChooserAction.Open,
        "Cancel", ResponseType.Cancel,
        "Open", ResponseType.Accept);
      dialog.SelectMultiple = true;
      var response = (ResponseType)dialog.Run ();
      if (response == ResponseType.Accept) {
        foreach (var file in dialog.Filenames) {
          try {
            mAgent.AddKeyFromFile (file, null, null);
          } catch (Exception ex) {
            Debug.Fail (ex.ToString ());
          }
        }
      }
      dialog.Destroy ();
      if (!(mAgent is Agent)) {
        ReloadKeyListView ();
      }
    }    

    protected void OnMRemoveButtonClicked (object sender, EventArgs e)
    {
      foreach (KeyNode node in mKeyNodeView.NodeSelection.SelectedNodes) {
        mAgent.RemoveKey (node.GetKey ());
      }
      if (!(mAgent is Agent)) {
        ReloadKeyListView ();
      }
    }    

    protected void OnMRemoveAllButtonClicked (object sender, EventArgs e)
    {
      mAgent.RemoveAllKeys ();
      if (!(mAgent is Agent)) {
        ReloadKeyListView ();
      }
    }    

    protected void OnMRefreshButtonClicked (object sender, EventArgs e)
    {
      ReloadKeyListView ();
    }

    private void mKeyNodeView_Selection_Changed (object sender, EventArgs e)
    {
      UpdateButtonStates ();
    }
  }
}

public static class KeyManagerWigetExt {

  public static int GetNodeCount(this NodeView aNodeView) {
      var count = 0;
      aNodeView.Model.Foreach ((TreeModelForeachFunc)
        delegate(TreeModel aModel, TreePath aPath, TreeIter aIter) {
        count ++;
        return true;
      });
      return count;
    }
}