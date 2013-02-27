using System;
using Gtk;
using dlech.SshAgentLib;

namespace SshAgentLib.GTK
{
  class MainClass
  {
    public static void Main (string[] args)
    {
      Application.Init ();
      KeyManagerWindow win = new KeyManagerWindow ();
      win.SetAgent (new UnixClient());
      win.Show ();
      Application.Run ();
    }
  }
}
