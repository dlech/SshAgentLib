using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using FileDialogExtenders;

namespace dlech.SshAgentLib.WinForms
{
  public partial class XPOpenFileDialog : FileDialogControlBase
  {
    public XPOpenFileDialog()
    {
      InitializeComponent();
    }

    public bool UseConfirmConstraintChecked
    {
      get { return mConfirmConstraintControl.Checked;  }
    }

    public bool UseLifetimeConstraintChecked
    {
      get { return mLifetimeConstraintControl.Checked; }
    }

    public uint LifetimeConstraintDuration
    {
      get { return mLifetimeConstraintControl.Lifetime; }
    }
  }
}
