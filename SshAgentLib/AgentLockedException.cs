using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Indicates that a method was called while the agent was locked
  /// </summary>
  public class AgentLockedException : Exception 
  {
    
  }
}
