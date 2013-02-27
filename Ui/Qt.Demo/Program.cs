using System;
using QtGui;
using QtCore;
using dlech.SshAgentLib;
using System.Diagnostics;

namespace dlech.SshAgentLib.Ui.QtAgent
{
  public class Program : QDialog
  {

    public Program ()
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
    public static int Main(String[] args)
    {
      if (Environment.OSVersion.Platform == PlatformID.Unix ||
          Environment.OSVersion.Platform == PlatformID.MacOSX)
      {
        Environment.SetEnvironmentVariable("LD_LIBRARY_PATH",
                                           Environment.CurrentDirectory);
      }
      new QApplication (args);
      new Program ();
      return QApplication.Exec ();
    }

  }
}
