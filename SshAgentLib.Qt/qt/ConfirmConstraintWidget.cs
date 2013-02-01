using System;
using QtCore;
using QtGui;

namespace dlech.SshAgentLib.QtAgent
{
  public partial class ConfirmConstraintWidget : QWidget
  {

    public bool Checked {
      get { return mCheckBox.Checked; }
      set { mCheckBox.Checked = value; }
    }

    public ConfirmConstraintWidget ()
    {
      SetupUi(this);
    }
  }
}

