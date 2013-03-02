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

