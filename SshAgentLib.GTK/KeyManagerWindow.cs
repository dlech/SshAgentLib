using System;
using Gtk;
using dlech.SshAgentLib;

public partial class KeyManagerWindow: Gtk.Window
{  
  public KeyManagerWindow (): base (Gtk.WindowType.Toplevel)
  {
    Build ();
  }
  
  protected void OnDeleteEvent (object sender, DeleteEventArgs a)
  {
    Application.Quit ();
    a.RetVal = true;
  }

  public void SetAgent (IAgent aAgent)
  {
    keymanagerwiget1.SetAgent (aAgent);
  }
}
