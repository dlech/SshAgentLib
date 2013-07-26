//
// KeyFileDialog.cs
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
using QtGui;
using QtCore;
using dlech.SshAgentLib;
using System.Collections.Generic;

namespace dlech.SshAgentLib.Ui.QtAgent
{
  public class KeyFileDialog : QFileDialog
  {
    private ConfirmConstraintWidget mConfirmWidget;
    private LifetimeConstraintWidget mLifetimeWidget;

    public KeyFileDialog (QWidget aParent = null,
                          string aCaption = "",
                          string aDirectory = "",
                          string aFilter = "") :
      base(aParent, aCaption, aDirectory, aFilter)
    {
      SetOption (QFileDialog.Option.DontUseNativeDialog, true);

      SetNameFilter (Tr ("All Files (*)") + ";;" +
        Tr ("PuTTY Private Key Files (*.ppk)")
      );
      fileMode = QFileDialog.FileMode.ExistingFiles;

       mConfirmWidget = new ConfirmConstraintWidget();
       mLifetimeWidget = new LifetimeConstraintWidget();

      // can't get layout as QGridLayout, so we are forced to add to bottom
      // and add extra widgets to take up space
      Layout.AddWidget (new QLabel(Tr ("Constraints:")));
      Layout.AddWidget (mConfirmWidget);
      Layout.AddWidget (new QWidget());
      Layout.AddWidget (new QWidget());
      Layout.AddWidget (mLifetimeWidget);
    }


    public List<Agent.KeyConstraint > GetConstraints ()
    {
      var list = new List<Agent.KeyConstraint > ();
      if (mConfirmWidget.Checked) {
        list.addConfirmConstraint ();
      }
      if (mLifetimeWidget.Checked) {
        list.addLifetimeConstraint (mLifetimeWidget.Lifetime);
      }
      return list;
    }
  }
}

