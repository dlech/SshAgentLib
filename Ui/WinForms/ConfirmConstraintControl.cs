using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace KeeAgent.UI
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
      BackColor = Color.Transparent;
    }
  }
}
