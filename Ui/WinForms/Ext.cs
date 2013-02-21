using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dlech.SshAgentLib;
using System.Windows.Forms;
using System.IO;

namespace dlech.SshAgentLib.WinForms
{
  /// <summary>
  /// Extension Methods
  /// </summary>
  public static class Ext
  {
    public static void AddKeysFromFiles(this IAgent aAgent, string[] aFileNames,
      ICollection<Agent.KeyConstraint> aConstraints = null)
    {
      foreach (var fileName in aFileNames) {
        try {
          aAgent.AddKeyFromFile(fileName, aConstraints);
        } catch (Exception ex) {
          MessageBox.Show(string.Format(Strings.errFileOpenFailed,
            fileName, ex.Message), Util.AssemblyTitle, MessageBoxButtons.OK,
            MessageBoxIcon.Error);
        }
        // TODO may want to return ICollection<ISshKey> with added keys 
        // to be more like other Add* methods
      }
    }

    public static ISshKey AddKeyFromFile(this IAgent aAgent, string aFileName,
      ICollection<Agent.KeyConstraint> aConstraints)
    {
      var getPassword = PasswordCallbackFactory(
        string.Format(Strings.msgEnterPassphrase, Path.GetFileName(aFileName)));
      return aAgent.AddKeyFromFile(aFileName, getPassword, aConstraints);
    }

    public static KeyFormatter.GetPassphraseCallback
      PasswordCallbackFactory(string aMessage)
    {
      return new KeyFormatter.GetPassphraseCallback(delegate()
      {
        var dialog = new PasswordDialog();
        dialog.Text = aMessage;
        var result = dialog.ShowDialog();
        if (result != DialogResult.OK) {
          return null;
        }
        return dialog.SecureEdit.SecureString;
      });
    }
  }
}
