using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
  public partial class ConfirmConstraintControl : UserControl
  {
    public bool Checked
    {
      get
      {
        return mConfirmCheckBox.Checked;
      }
      set
      {
        mConfirmCheckBox.Checked = value;
      }
    }

    public ConfirmConstraintControl()
    {
      InitializeComponent();
      if (Type.GetType("Mono.Runtime") != null) {
        mConfirmCheckBox.AutoSize = false;
        mConfirmCheckBox.Width = 200;
        AutoSize = false;
        Width = 200;
      }
      BackColor = Color.Transparent;
    }
  }
}
