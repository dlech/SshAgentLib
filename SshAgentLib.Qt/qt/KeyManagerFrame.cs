using QtCore;
using QtGui;
using dlech.SshAgentLib;
using System;
using System.Diagnostics;
using System.Collections.Generic;

namespace dlech.SshAgentLib.QtAgent
{
  public partial class KeyManagerFrame : QWidget
  {
    private IAgent mAgent;
    private KeyTableModel mTableModel;

    private class KeyTableModel : QAbstractListModel
    {

      private List<KeyWrapper> mKeyList = new List<KeyWrapper> ();

      public override int ColumnCount (QModelIndex aParent)
      {
        return 6;
      }

      public override int RowCount (QModelIndex aParent)
      {
        return mKeyList.Count;
      }

      public override object Data (QModelIndex aIndex,
                                   int role = (int)Qt.ItemDataRole.DisplayRole)
      {
        return mKeyList;
      }

      public override QModelIndex Parent (QModelIndex aParent)
      {
        return null;
      }
    }

    public KeyManagerFrame ()
    {
      SetupUi (this);

      mTableModel = new KeyTableModel ();
      mTableView .Model = mTableModel;

      mLockButton.Clicked += mLockButton_Clicked;
      mUnlockButton.Clicked += mUnlockButton_Clicked;
      mAddButton.Clicked += mAddButton_Clicked;
      mRemoveButton.Clicked += mRemoveButton_Clicked;
      mRemoveAllButton.Clicked += mRemoveAllButton_Clicked;
      mRefreshButton.Clicked += mRefreshButton_Clicked;

    }

    public void SetAgent (IAgent aAgent)
    {
      mAgent = aAgent;      
      ReloadData ();
    }

    private void ReloadData ()
    {
      foreach (var key in mAgent.GetAllKeys ()) {
        //mTableModel.AppendRow ();
      }
      UpdateButtons ();
    }

    private void UpdateButtons ()
    {
      // TODO - remove buttons
      var agent = mAgent as Agent;
      if (agent == null) {
        mLockButton.Enabled = true;
        mUnlockButton.Enabled = true;
      } else {
        mLockButton.Enabled = agent.IsLocked;
        mUnlockButton.Enabled = !agent.IsLocked;
      }
    }

    [Q_SLOT]
    private void mLockButton_Clicked ()
    {
      // TODO - pasword dialog
      try {
        mAgent.Lock (new byte[0]);
      } catch (AgentLockedException) {
        // TODO - message dialog
      } catch (Exception ex) {
        Debug.Fail (ex.ToString ());
      }
      if (mAgent is AgentClient) {
        UpdateButtons ();
      }
    }

    [Q_SLOT]
    private void mUnlockButton_Clicked ()
    {
    }

    [Q_SLOT]
    private void mAddButton_Clicked ()
    {
    }

    [Q_SLOT]
    private void mRemoveButton_Clicked ()
    {
    }

    [Q_SLOT]
    private void mRemoveAllButton_Clicked ()
    {
    }

    [Q_SLOT]
    private void mRefreshButton_Clicked ()
    {
    }

  }

}
