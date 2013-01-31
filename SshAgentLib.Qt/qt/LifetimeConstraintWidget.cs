using System;
using QtCore;
using QtGui;

namespace dlech.SshAgentLib.QtAgent
{
  public partial class LifetimeConstraintWidget : QWidget
  {
    private LifetimeValidator mLifetimeValidator;

    public uint DefaultLifetime { get; set; }

    public LifetimeConstraintWidget ()
    {
      DefaultLifetime = 600;

      SetupUi(this);
       
      mLifetimeValidator = new LifetimeValidator(mLineEdit);
      mLineEdit.Validator = mLifetimeValidator;

      mCheckBox.StateChanged += mCheckBox_StateChanged;

    }

    [Q_SLOT]
    private void mCheckBox_StateChanged (int aState)
    {
      if (aState == (int)Qt.CheckState.Checked) {
        if (string.IsNullOrWhiteSpace (mLineEdit.Text)) {
          mLineEdit.Text = DefaultLifetime.ToString ();
        }
        mLineEdit.SelectAll ();
      } 
    }

    
    private class LifetimeValidator : QValidator {

      private QLineEdit mLineEdit;

      public LifetimeValidator(QLineEdit aLineEdit) {
        mLineEdit = aLineEdit;
      }

      public override void Fixup (string aInput)
      { 
        // seems to be a bug in Qyoto, the arg should have ref modifer
        if (string.IsNullOrEmpty (aInput)) {
          //aInput = "0";
          mLineEdit.Text = "0";
        }
      }

      public override State Validate (string aInput, ref int aPos)
      {
        if (string.IsNullOrEmpty (aInput)) {
          return State.Intermediate;
        }
        uint u;
        return uint.TryParse (aInput, out u) ? State.Acceptable : State.Invalid;
      }

    }

  }
}

