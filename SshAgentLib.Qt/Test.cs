using System;
using QtGui;
using QtCore;
using dlech.SshAgentLib;
using System.Diagnostics;

namespace dlech.SshAgentLib.QtAgent
{
  public class Test : QDialog
  {

    IAgent mAgent;

    public Test ()
    {
      WindowTitle = Tr("SSH Key Manager");
      SizeGripEnabled = true;

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

