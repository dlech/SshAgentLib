//
// SshAgentLibTestsSetup.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System.Diagnostics;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{
  [SetUpFixture()]
  public class SshAgentLibTestsSetup
  {
    [OneTimeSetUp]
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
