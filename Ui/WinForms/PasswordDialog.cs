using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using System.Security;

namespace dlech.SshAgentLib.WinForms
{
  partial class PasswordDialog : Form
  {

    private SecureEdit mSecureEdit;

    public SecureEdit SecureEdit
    {
      get
      {
        return mSecureEdit;
      }
    }

    public PasswordDialog()
    {
      InitializeComponent();
      mSecureEdit = new SecureEdit();
    }

    private void PasswordDialog_Load(object sender, EventArgs e)
    {
      mSecureEdit.Attach(passwordTextBox, null, true);
      Activate();
    }

    private void PasswordDialog_FormClosing(object sender, FormClosingEventArgs e)
    {
      mSecureEdit.Detach();
    }

    private void okButton_Click(object sender, EventArgs e)
    {
      DialogResult = DialogResult.OK;
      Close();
    }

    protected override void OnShown(EventArgs e)
    {
      base.OnShown(e);
      passwordTextBox.Focus();
    }

  }
}
