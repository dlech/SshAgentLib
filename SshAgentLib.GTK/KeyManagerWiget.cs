using System;
using System.Data;
using System.Linq;
using dlech.SshAgentLib;
using System.ComponentModel;

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

      mKeyNodeView.AppendColumn ("C", new Gtk.CellRendererToggle(), "active", 0);
      mKeyNodeView.AppendColumn ("L", new Gtk.CellRendererToggle(), "active", 1);
      mKeyNodeView.AppendColumn ("Size", new Gtk.CellRendererText(), "text", 2);
      mKeyNodeView.AppendColumn ("Type", new Gtk.CellRendererText(), "text", 3);
      mKeyNodeView.AppendColumn ("Fingerprint", new Gtk.CellRendererText(), "text", 4);
      mKeyNodeView.AppendColumn ("Comment", new Gtk.CellRendererText(), "text", 5);

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
        var messageDialog =
          new Gtk.MessageDialog(null, Gtk.DialogFlags.Modal , 
                                Gtk.MessageType.Error , Gtk.ButtonsType.Close ,
                                "failed"/*Strings.errListKeysFailed*/);
        messageDialog.Run ();
        messageDialog.Destroy ();
      }
      //UpdateVisibility();
      //UpdateButtonStates();
    }

    private void AgentLockHandler(object aSender, Agent.LockEventArgs aArgs)
    {
//      Invoke((MethodInvoker)delegate()
//      {
//        UpdateVisibility();
//        UpdateButtonStates();
//      });
    }

    private void AgentKeyListChangeHandler(object aSender,
      Agent.KeyListChangeEventArgs aArgs)
    {
//      if (IsDisposed) {
//        return;
//      }
      switch (aArgs.Action) {
        case Agent.KeyListChangeEventAction.Add:
          Gtk.Application.Invoke(delegate(object aSender1, EventArgs aEventArgs1)
          {
            //mKeyCollection.Add(new KeyWrapper(aArgs.Key));
            //UpdateVisibility();
          });
          break;
        case Agent.KeyListChangeEventAction.Remove:
          Gtk.Application.Invoke(delegate(object aSender1, EventArgs aEventArgs1)
          {
            var matchFingerprint = aArgs.Key.GetMD5Fingerprint().ToHexString();
//            var matches = mKeyCollection.Data.Where(k =>
//              k.Fingerprint == matchFingerprint).ToList();
//            foreach (var key in matches) {
//              mKeyCollection.Remove(key);
//            }
            //UpdateVisibility();
          });
          break;
      }
      //UpdateButtonStates();
    }


    protected void OnMLockButtonClicked (object sender, EventArgs e)
    {
      throw new System.NotImplementedException ();
    }    protected void OnMUnlockButtonClicked (object sender, EventArgs e)
    {
      throw new System.NotImplementedException ();
    }    protected void OnMAddButtonClicked (object sender, EventArgs e)
    {
      throw new System.NotImplementedException ();
    }    protected void OnMRemoveButtonClicked (object sender, EventArgs e)
    {
      throw new System.NotImplementedException ();
    }    protected void OnMRemoveAllButtonClicked (object sender, EventArgs e)
    {
      throw new System.NotImplementedException ();
    }    protected void OnMRefreshButtonClicked (object sender, EventArgs e)
    {
      throw new System.NotImplementedException ();
    }
  }
}

