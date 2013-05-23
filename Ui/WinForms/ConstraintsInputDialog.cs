using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
  public partial class ConstraintsInputDialog : Form
  {
    public bool ConfirmConstraintChecked
    {
      get { return mConfirmConstraintControl.Checked; }
    }

    public bool LifetimeConstraintChecked
    {
      get { return mLifetimeConstraintControl.Checked; }
    }

    public uint LifetimeDuration
    {
      get { return mLifetimeConstraintControl.Lifetime; }
    }

    public ConstraintsInputDialog()
    {
      InitializeComponent();
    }

    private void mOKButton_Click(object sender, EventArgs e)
    {
      if (LifetimeConstraintChecked && LifetimeDuration == 0) {
        MessageBox.Show("Invalid Lifetime", "Error", MessageBoxButtons.OK,
          MessageBoxIcon.Exclamation);
      } else {
        DialogResult = DialogResult.OK;
        Close();
      }
    }
  }
}
