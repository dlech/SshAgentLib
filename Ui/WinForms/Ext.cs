//
// Ext.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013,2015 David Lechner
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
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
  /// <summary>
  /// Extension Methods
  /// </summary>
  public static class Ext
  {
    public static void AddKeysFromFiles(this IAgent agent, string[] fileNames,
      ICollection<Agent.KeyConstraint> constraints = null)
    {
      KeyFormatter.GetPassphraseCallback getPassword = null;
      foreach (var fileName in fileNames) {
        try {
          try {
            // try using the previous passphrase
            if (getPassword == null) {
              throw new Exception("No previous passphrase.");
            }
            agent.AddKeyFromFile(fileName, constraints, getPassword);
          } catch {
            // if the previous passphrase does not work, ask for a new passphrase
            getPassword = PasswordCallbackFactory(
              string.Format(Strings.msgEnterPassphrase, Path.GetFileName(fileName)));
            agent.AddKeyFromFile(fileName, constraints, getPassword);
          }
        } catch (PpkFormatterException) {
          MessageBox.Show(string.Format(
            "Error opening file '{0}'\n" +
            "Possible causes:\n" +
            "\n" +
            "- Passphrase was entered incorrectly\n" +
            "- File is corrupt",
            fileName), Util.AssemblyTitle, MessageBoxButtons.OK,
            MessageBoxIcon.Error);
        } catch (AgentNotRunningException) { 
          MessageBox.Show ("Could not add key because no SSH agent was found." +
            " Please make sure your SSH agent program is running (e.g. Pageant).",
            Util.AssemblyTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
        } catch (Exception ex) {
          MessageBox.Show(string.Format(Strings.errFileOpenFailed,
            fileName, ex.Message), Util.AssemblyTitle, MessageBoxButtons.OK,
            MessageBoxIcon.Error);
        }
        // TODO may want to return ICollection<ISshKey> with added keys 
        // to be more like other Add* methods
      }
    }

    public static ISshKey AddKeyFromFile(this IAgent agent, string fileName,
      ICollection<Agent.KeyConstraint> constraints,
      KeyFormatter.GetPassphraseCallback getPassword = null)
    {
      if (getPassword == null) {
        getPassword = PasswordCallbackFactory(
          string.Format(Strings.msgEnterPassphrase, Path.GetFileName(fileName)));
      }
      return agent.AddKeyFromFile(fileName, getPassword, constraints);
    }

    public static KeyFormatter.GetPassphraseCallback
      PasswordCallbackFactory(string message)
    {
      SecureString passphrase = null;
      return new KeyFormatter.GetPassphraseCallback(delegate(string comment)
      {
        if (passphrase == null) {
          var dialog = new PasswordDialog();
          dialog.Text = message;
          if (!string.IsNullOrWhiteSpace(comment)) {
            dialog.Text += string.Format(" ({0})", comment);
          }
          var result = dialog.ShowDialog();
          if (result != DialogResult.OK) {
            return null;
          }
          passphrase = dialog.SecureEdit.SecureString;
        }
        return passphrase;
      });
    }
  }
}
