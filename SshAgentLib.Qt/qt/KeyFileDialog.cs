using System;
using QtGui;
using QtCore;

namespace dlech.SshAgentLib.QtAgent
{
  public class KeyFileDialog : QFileDialog
  {
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
             
      var confirmCheckBox =
          new QCheckBox (Tr ("Require confirmation"));
      confirmCheckBox.ToolTip =
          Tr ("User confirmation will be required each time this key is used to authenticate");

      var lifetimeCheckBox = new QCheckBox (Tr ("Lifetime"));
      lifetimeCheckBox.ToolTip =
          Tr ("Key will automatically be removed from agent after specified lifetime");
      var lifeTimelineEdit = new QLineEdit ();
      lifeTimelineEdit.SetFixedWidth (50);
      var lifetimeLabel = new QLabel (Tr ("Seconds"));
          
      var confirmWidget = new QWidget();
      var confirmLayout = new QHBoxLayout(confirmWidget);
      confirmLayout.SetContentsMargins (0,0,0,0);
      confirmLayout.AddWidget (confirmCheckBox);
      confirmLayout.AddSpacerItem (new QSpacerItem(0, 0,
                                                   QSizePolicy.Policy.Expanding,
                                                   QSizePolicy.Policy.Ignored));

      var lifetimeWidget = new QWidget();
      var lifetimeLayout = new QHBoxLayout(lifetimeWidget);
      lifetimeLayout.SetContentsMargins (0,0,0,0);
      lifetimeLayout.AddWidget (lifetimeCheckBox);
      lifetimeLayout.AddWidget (lifeTimelineEdit);
      lifetimeLayout.AddWidget (lifetimeLabel);
      lifetimeLayout.AddSpacerItem (new QSpacerItem(0, 0,
                                                   QSizePolicy.Policy.Expanding,
                                                   QSizePolicy.Policy.Ignored));

      // can't get layout as QGridLayout, so we are forced to add to bottom
      // and one item at a time
      Layout.AddWidget (new QLabel(Tr ("Constraints:")));
      Layout.AddWidget (confirmWidget);
      Layout.AddWidget (new QWidget());
      Layout.AddWidget (new QWidget());
      Layout.AddWidget (lifetimeWidget);
    }

  }
}

