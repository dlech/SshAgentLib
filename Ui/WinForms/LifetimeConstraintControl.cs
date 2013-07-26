﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using dlech.SshAgentLib;

namespace dlech.SshAgentLib.WinForms
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

    /// <summary>
    /// returns the lifetime entered in the text box or 0 if entered value is invalid
    /// </summary>
    public uint Lifetime
    {
      get
      {
        uint lifetime;
        if (uint.TryParse(mLifetimeTextBox.Text, out lifetime)) {
          return lifetime;
        }
        return 0;
      }
      set
      {
        mLifetimeTextBox.Text = value.ToString();
      }
    }


    public LifetimeConstraintControl()
    {
      InitializeComponent();
      if (Type.GetType ("Mono.Runtime") != null) {
        AutoSize = false;
        Width = 250;
      }
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