using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.SshAgentLib
{
  public delegate void SshKeyEventHandler(object sender, SshKeyEventArgs e);

  public class SshKeyEventArgs : EventArgs
  {
    public ISshKey Key { get; private set; }

    public SshKeyEventArgs(ISshKey key)
    {
      this.Key = key;
    }
  }
}
