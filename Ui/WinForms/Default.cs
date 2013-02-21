// -----------------------------------------------------------------------
// <copyright file="Default.cs" company="">
// TODO: Update copyright text.
// </copyright>
// -----------------------------------------------------------------------

namespace dlech.SshAgentLib.WinForms
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;
  using dlech.SshAgentLib;
  using System.Windows.Forms;

  /// <summary>
  /// Default implementation of delegate methods
  /// </summary>
  public static class Default
  {
    public static bool ConfirmCallback(ISshKey key)
    {
      var result = MessageBox.Show(
        string.Format(Strings.askConfirmKey, key.Comment, key.GetMD5Fingerprint().ToHexString()),
        Util.AssemblyTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Question,
        MessageBoxDefaultButton.Button2
      );
      if (result == DialogResult.Yes) {
        return true;
      }
      return false;
    }
  }
}
