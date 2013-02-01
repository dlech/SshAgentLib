using System;
using System.Security;
using QtGui;
using System.Text;
using QtCore;

namespace dlech.SshAgentLib.QtAgent
{
  public partial class PassphraseDialog : QDialog
  {
    private SecureEdit mSecureEdit;

    public PassphraseDialog()
    {
      SetupUi(this);
      Message = string.Empty;

      mSecureEdit = new SecureEdit();

      ShowEvent += PassphraseDialog_ShowEvent;
      HideEvent += PassphraseDialog_HideEvent;
    }

    public string Message {
      get {
        return mMessageLabel.Text;
      }
      set {
        mMessageLabel.Text = value;
        mMessageLabel.Visible = !string.IsNullOrWhiteSpace(value);
      }
    }

    public byte[] GetPassphrase()
    {
      return mSecureEdit.ToUtf8();
    }

//    public SecureString GetSecurePassphrase()
//    {
//      return mSecureEdit.SecureString;
//    }

    [Q_SLOT]
    private void PassphraseDialog_ShowEvent(object aSender,
                                            QEventArgs<QShowEvent> aEventArgs)
    {
      mSecureEdit.Attach(mPassphraseLineEdit, true);
      mPassphraseLineEdit.FocusWidget();
    }

    [Q_SLOT]
    private void PassphraseDialog_HideEvent(object aSender,
                                            QEventArgs<QHideEvent> aEventArgs)
    {
      mSecureEdit.Detach();
    }
  }
}
