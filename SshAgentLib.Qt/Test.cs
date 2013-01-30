using System;
using QtGui;
using QtCore;
using QtUiTools;
using dlech.SshAgentLib;
using System.Diagnostics;

namespace dlech.SshAgentLib.QtAgent
{
  public class Test : QWidget
  {
   
    IAgent mAgent;

    public Test ()
    {
      WindowTitle = "SSH Key Manager";
      var keyManager = new KeyManagerFrame ();
      keyManager.SetAgent (new UnixClient ());
      var layout = new QVBoxLayout ();
      layout.AddWidget (keyManager);
      layout.ContentsMargins = new QMargins (0, 0, 0, 0);
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

