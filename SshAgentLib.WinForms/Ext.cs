using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dlech.SshAgentLib;
using System.Windows.Forms;
using dlech.SshAgentLib.WinForms;
using System.IO;
using SshAgentLib.WinForm;

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
      }
    }

    public static void AddKeyFromFile(this IAgent aAgent, string aFileName,
      ICollection<Agent.KeyConstraint> aConstraints)
    {
      var getPassword = PasswordCallbackFactory(
        string.Format(Strings.msgEnterPassphrase, Path.GetFileName(aFileName)));
      var success = aAgent.AddKeyFromFile(aFileName, getPassword, aConstraints);
      if (!success) {
        throw new Exception(Strings.errAddKeyFailed);
      }
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
