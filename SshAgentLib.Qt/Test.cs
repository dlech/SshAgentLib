using System;
using QtGui;
using QtCore;
using QtUiTools;

namespace SshAgentLib.Qt
{
  public class Test : QWidget
  {
   
    public Test ()
    {
      var loader = new QUiLoader (this);   
      QWidget keyManager;

      using (var file = new QFile("../../qt/KeyManagerFrame.ui")) {
        file.Open (QIODevice.OpenModeFlag.ReadOnly);
        keyManager = loader.Load (file);
        file.Close ();
      }
      WindowTitle = "SSH Key Manager";
      var layout = new QVBoxLayout ();
      layout.AddWidget (keyManager);
      layout.ContentsMargins  = new QMargins(0,0,0,0);
      Layout = layout;
        
      Show ();
    }

    [STAThread]
    public static int Main (String[] args)
    {
      new QApplication (args);
      new Test ();
      return QApplication.Exec ();
    }

  }
}

