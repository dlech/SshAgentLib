using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using dlech.SshAgentLib;

namespace KeeAgent.UI
{
  public partial class LifetimeConstraintControl : UserControl
  {
    public bool Checked
    {
      get
      {
        return mLifetimeCheckBox.Checked;
      }
      set
      {
        mLifetimeCheckBox.Checked = value;
      }
    }

    public uint Lifetime
    {
      get
      {
        return uint.Parse(mLifetimeTextBox.Text);
      }
      set
      {
        mLifetimeTextBox.Text = value.ToString();
      }
    }


    public LifetimeConstraintControl()
    {
      InitializeComponent();
    }

    private void mLifetimeCheckBox_CheckedChanged(object sender, EventArgs e)
    {
      mLifetimeTextBox.Enabled = mLifetimeCheckBox.Checked;
      mTimeUnitsLabel.Enabled = mLifetimeCheckBox.Checked;
      if (mLifetimeCheckBox.Checked) {
        mLifetimeTextBox.SelectAll();
        mLifetimeTextBox.Focus();
      }
    }

    private void mLifetimeTextBox_Validating(object sender, CancelEventArgs e)
    {
      uint testValue = 0;
      if (string.IsNullOrWhiteSpace(mLifetimeTextBox.Text)) {
        mLifetimeTextBox.Text = "0";
      }
      if (!uint.TryParse(mLifetimeTextBox.Text, out testValue)) {
        MessageBox.Show("Invalid lifetime.", Util.AssemblyTitle,
          MessageBoxButtons.OK, MessageBoxIcon.Warning);
        e.Cancel = true;
      }
    }
  }
}
