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
      if (Type.GetType ("Mono.Runtime") != null) {
        mConfirmConstraintControl.AutoSize = false;
        mConfirmConstraintControl.Size =
        new Size (200, mConfirmConstraintControl.Height);
        mLifetimeConstraintControl.AutoSize = false;
        mLifetimeConstraintControl.Size =
        new Size (200, mLifetimeConstraintControl.Height);
        mOKButton.Location = new Point (mOKButton.Location.X,
                                     mOKButton.Location.Y - 20);
        Size = new Size (Width, Height + 20);
      }
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
