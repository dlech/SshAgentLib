using System;
using dlech.SshAgentLib;

namespace dlech.SshAgentLib.Ui.Common
{
  public abstract class AgentUi
  {
    private IAgent mAgent;

    public AgentUi(IAgent aAgent)
    {
      mAgent = aAgent;
    }


  }
}

