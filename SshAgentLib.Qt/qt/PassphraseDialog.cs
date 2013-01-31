using System;
using System.Security;
using QtGui;

namespace dlech.SshAgentLib.QtAgent
{
  public partial class PassphraseDialog : QDialog
  {
    public PassphraseDialog ()
    {
      SetupUi (this);
      Message = string.Empty;
    }

    public string Message {
      get {
        return mMessageLabel.Text;
      }
      set {
        mMessageLabel.Text = value;
        mMessageLabel.Visible = !string.IsNullOrWhiteSpace (value);
      }
    }

    public SecureString Passphrase {
      get {
        var securePassphrase = new SecureString ();
        foreach (char c in mPassphraseLineEdit.Text) {
          securePassphrase.AppendChar (c);
        }
        return securePassphrase;
      }
    }
  }
}
