using QtCore;
using QtGui;
using dlech.SshAgentLib;
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;

namespace dlech.SshAgentLib.QtAgent
{
  public partial class KeyManagerFrame : QWidget
  {
    private IAgent mAgent;
    private KeyTableModel mTableModel;

    private class KeyTableModel : QAbstractTableModel
    {

      private List<KeyWrapper> mKeyList = new List<KeyWrapper> ();

//      public override bool InsertRows (int row, int count, QModelIndex parent)
//      {
//        BeginInsertRows (new QModelIndex(), row, row + count - 1);
//
//        EndInsertRows ();
//      }

      public void AddKey (ISshKey aKey)
      {
        var position = mKeyList.Count;
        BeginInsertRows (new QModelIndex (), position, position);
        mKeyList.Add (new KeyWrapper (aKey));
        EndInsertRows ();
      }

      public override int ColumnCount (QModelIndex aParent)
      {
        return 6;
      }

      public override int RowCount (QModelIndex aParent)
      {
        return mKeyList.Count;
      }

      public override object HeaderData (int aSection,
                                         Orientation aOrientation,
                                         int aRole)
      {
        if (aOrientation == Orientation.Horizontal) {
          var role = (ItemDataRole)aRole;
          switch (role) {
            case ItemDataRole.DisplayRole:
              switch (aSection) {
                case 0:
                  return Tr ("C");
                case 1:
                  return Tr ("L");
                case 2: 
                  return Tr ("Type");
                case 3:
                  return Tr ("Size");
                case 4:
                  return Tr ("Fingerprint");
                case 5:
                  return Tr ("Comment");
              }
              break;
            case ItemDataRole.ToolTipRole:
              switch (aSection) {
                case 0:
                  return Tr ("Confirm Constraint");
                case 1:
                  return Tr ("Lifetime Constraint");
              }
              break;
          } 
        }
        return base.HeaderData (aSection, aOrientation, aRole);
      }

      public override object Data (QModelIndex aIndex,
                                   int aRole = (int)ItemDataRole.DisplayRole)
      {
        if (!aIndex.IsValid) {
          return new QVariant ();
        }
        if (aIndex.Row >= mKeyList.Count || aIndex.Row < 0) {
          return new QVariant ();
        }
        var role = (ItemDataRole)aRole;
        var key = mKeyList [aIndex.Row];
        if (role == ItemDataRole.DisplayRole) {
          switch (aIndex.Column) {
            case 0:
              return key.Confirm;
            case 1:
              return key.Lifetime;
            case 2: 
              return key.Type;
            case 3:
              return key.Size;
            case 4:
              return key.Fingerprint;
            case 5:
              return key.Comment;
            default:
              return new QVariant ();
          } 
        } else if (role == ItemDataRole.CheckStateRole) {
          switch (aIndex.Column) {
            case 0:
              return key.Confirm ? CheckState.Checked : CheckState.Unchecked;
            case 1:
              return key.Lifetime ? CheckState.Checked : CheckState.Unchecked;
            default :
              return new QVariant();
          }
        }
        return new QVariant ();
      }

      public override QModelIndex Parent (QModelIndex aParent)
      {
        return new QModelIndex ();
      }
    }

    public KeyManagerFrame ()
    {
      SetupUi (this);

      mTableModel = new KeyTableModel ();

      //mTableWidget .Model = mTableModel;
      mTableWidget.SelectionModel.SelectionChanged +=
        mTableWidget_SelectionModel_SelectionChanged;

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
      var agent = aAgent as Agent;
      if (agent == null) {
        mTableWidget.HideColumn (0);
        mTableWidget.HideColumn (1);
      } else {
        mTableWidget.ShowColumn (0);
        mTableWidget.ShowColumn (1);
      }
      ReloadData ();
    }

    [Q_SLOT]
    private void mTableWidget_SelectionModel_SelectionChanged (
      QItemSelection aSelected, QItemSelection aDeselected)
    {
      UpdateButtons ();
    }

    private void ReloadData ()
    {
      foreach (var key in mAgent.GetAllKeys ()) {
        var newRowIndex = mTableWidget.RowCount; 
        mTableWidget.Model.InsertRow (newRowIndex);
        mTableWidget.SetItem (newRowIndex, 0, new QTableWidgetItem(key.HasConstraint (Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM).ToString ()));
        mTableWidget.SetItem (newRowIndex, 1, new QTableWidgetItem(key.HasConstraint (Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME).ToString ()));
        mTableWidget.SetItem (newRowIndex, 2, new QTableWidgetItem(key.Algorithm.GetIdentifierString ()));
        mTableWidget.SetItem (newRowIndex, 3, new QTableWidgetItem(key.Size.ToString ()));
        mTableWidget.SetItem (newRowIndex, 4, new QTableWidgetItem(key.GetMD5Fingerprint ().ToHexString ()));
        mTableWidget.SetItem (newRowIndex, 5, new QTableWidgetItem(key.Comment));

        //mTableModel.AddKey (key);
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
      using (var dialog = new PassphraseDialog ()) {
        dialog.Exec ();
        if (dialog.Result == (int)QDialog.DialogCode.Rejected) {
          return;
        }
        var passphrase = Encoding.UTF8.GetBytes (dialog.mPassphraseLineEdit.Text);
        try {
          mAgent.Lock (passphrase);
        } catch (AgentLockedException) {
          QMessageBox.Critical (this, "Error", "Agent is already locked");
        } catch (AgentFailureException) {
          QMessageBox.Critical (this, "Agent Failure",
                              "Possible causes:" +
            "<ul>" +
            "<li>Agent is already locked</li>" +
            "<li>Agent does not support locking.</li>" +
            "</ul>"
          );
        } catch (Exception ex) {
          Debug.Fail (ex.ToString ());
        }
      }
      if (mAgent is Agent) {
        UpdateButtons ();
      } else {      
        ReloadData ();
      }
    }

    [Q_SLOT]
    private void mUnlockButton_Clicked ()
    {
      using (var dialog = new PassphraseDialog ()) {
        dialog.Exec ();
        if (dialog.Result == (int)QDialog.DialogCode.Rejected) {
          return;
        }
        var passphrase = Encoding.UTF8.GetBytes (dialog.mPassphraseLineEdit.Text);
        try {
          mAgent.Unlock (passphrase);
        } catch (AgentLockedException) {
          QMessageBox.Critical (this, "Error", "Agent is already locked");
        } catch (AgentFailureException) {
          QMessageBox.Critical (this, "Agent Failure",
                              "Possible causes:" +
            "<ul>" +
            "<li>Passphrase was incorrect</li>" +
            "<li>Agent is already unlocked</li>" +
            "<li>Agent does not support locking</li>" +
            "</ul>"
          );
        } catch (Exception ex) {
          Debug.Fail (ex.ToString ());
        }
      }
      if (mAgent is Agent) {
        UpdateButtons ();
      } else {      
        ReloadData ();
      }
    }

    [Q_SLOT]
    private void mAddButton_Clicked ()
    {
      if (mAgent is Agent) {
        UpdateButtons ();
      } else {      
        ReloadData ();
      }
    }

    [Q_SLOT]
    private void mRemoveButton_Clicked ()
    {
      if (mAgent is Agent) {
        UpdateButtons ();
      } else {      
        ReloadData ();
      }
    }

    [Q_SLOT]
    private void mRemoveAllButton_Clicked ()
    {
      if (mAgent is Agent) {
        UpdateButtons ();
      } else {      
        ReloadData ();
      }
    }

    [Q_SLOT]
    private void mRefreshButton_Clicked ()
    {
      ReloadData ();
    }

  }

}
