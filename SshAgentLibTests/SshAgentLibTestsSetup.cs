// -----------------------------------------------------------------------
// <copyright file="SshAgentLibTestsSetup.cs" company="">
// TODO: Update copyright text.
// </copyright>
// -----------------------------------------------------------------------

namespace dlech.SshAgentLibTests
{
  using System;
  using System.Collections.Generic;
  using System.Linq;
  using System.Text;
  using NUnit.Framework;
  using System.Diagnostics;

  [SetUpFixture()]
  public class SshAgentLibTestsSetup
  {
    [SetUp]
    public void RunBeforeAnyTests()
    {
      // remove the debug listener so we don't get dialogs popping up
      TraceListener removeListener = null;
      foreach (TraceListener listener in Debug.Listeners) {
        if (listener is DefaultTraceListener) {
          removeListener = listener;
          break;
        }
      }
      Debug.Listeners.Remove(removeListener);

      // add new listener so we get fail the test instead
      Debug.Listeners.Add(new FailOnAssertListener());
    }

    // 
    public class FailOnAssertListener : TraceListener
    {
      public override void Fail(string aMessage)
      {
        Assert.Inconclusive(aMessage);
      }

      public override void Fail(string aMessage, string aDetailMessage)
      {
        Assert.Inconclusive(aMessage, aDetailMessage);
      }

      public override void Write(string aString) { }
      public override void WriteLine(string aString) { }
    }

  }
}
