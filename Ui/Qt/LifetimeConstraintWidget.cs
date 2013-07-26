//
// LifetimeConstraintWidget.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using QtCore;
using QtGui;
using dlech.SshAgentLib;
using System.ComponentModel;

namespace dlech.SshAgentLib.Ui.QtAgent
{
  public partial class LifetimeConstraintWidget : QWidget
  {
    private const uint cDefaultLifetime = 600;
    private uint pLifetime;
    private LifetimeValidator mLifetimeValidator;

    [DefaultValue(cDefaultLifetime)]
    public uint Lifetime {
      get {
        uint value = pLifetime;
        if (uint.TryParse(mLineEdit.Text, out value)) {
          return value;
        }
        return pLifetime;
      }
      set {
        if (mCheckBox.Checked && pLifetime != value) {
          mCheckBox.Text = value.ToString();
        }
        pLifetime = value;

      }
    }

    public bool Checked {
      get { return mCheckBox.Checked; }
      set { mCheckBox.Checked = value; }
    }

    public LifetimeConstraintWidget()
    {
      SetupUi(this);

      mLifetimeValidator = new LifetimeValidator(mLineEdit);
      mLineEdit.Validator = mLifetimeValidator;

      mCheckBox.StateChanged += mCheckBox_StateChanged;

    }

    [Q_SLOT]
    private void mCheckBox_StateChanged(int aState)
    {
      if (aState == (int)Qt.CheckState.Checked) {
        if (string.IsNullOrWhiteSpace(mLineEdit.Text)) {
          mLineEdit.Text = Lifetime.ToString();
        }
        mLineEdit.SelectAll();
      } else {
        mLineEdit.Text = string.Empty;
      }
    }


    private class LifetimeValidator : QValidator
    {

      private QLineEdit mLineEdit;

      public LifetimeValidator(QLineEdit aLineEdit)
      {
        mLineEdit = aLineEdit;
      }

      public override void Fixup(string aInput)
      {
        // seems to be a bug in Qyoto, the arg should have ref modifer
        if (string.IsNullOrEmpty(aInput)) {
          //aInput = "0";
          mLineEdit.Text = "0";
        }
      }

      public override State Validate(string aInput, ref int aPos)
      {
        if (string.IsNullOrEmpty(aInput)) {
          return State.Intermediate;
        }
        uint u;
        return uint.TryParse(aInput, out u) ? State.Acceptable : State.Invalid;
      }

    }

  }
}

