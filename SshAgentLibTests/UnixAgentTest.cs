//
// UnixAgentTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
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

using System;
using System.IO;
using System.Net.Sockets;
using System.Reflection;
using dlech.SshAgentLib;
using Mono.Unix;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{
  [TestFixture()]
  [Platform(Exclude="Win")]
  public class UnixAgentTest
  {
    /// <summary>
    /// Tests that the temp dir is deleted on Dispose/Finalize.
    /// </summary>
    [Test()]
    public void TestUnixAgent()
    {
      string socketDir;
      string socketPathEnv;
      string pidEnv;
      using (UnixAgent agent = new UnixAgent()) {
        socketDir = GetField<string>(agent, "socketDir");
        int pid = UnixProcess.GetCurrentProcessId();
        socketPathEnv = Environment
        .GetEnvironmentVariable(UnixAgent.SSH_AUTHSOCKET_ENV_NAME);
        pidEnv = Environment
        .GetEnvironmentVariable(UnixAgent.SSH_AGENTPID_ENV_NAME);

        Assert.That(socketPathEnv.Contains(socketDir), Is.True,
          "Failed to set environment variable " +
          UnixAgent.SSH_AUTHSOCKET_ENV_NAME
        );
        Assert.That(pidEnv, Is.EqualTo(pid.ToString()),
          "Failed to set environment variable " +
          UnixAgent.SSH_AGENTPID_ENV_NAME
        );

        using (Mono.Unix.UnixClient client =
               new Mono.Unix.UnixClient (socketPathEnv)) {
          using (NetworkStream stream = client.GetStream ()) {
            stream.Write(new byte[] { 0 }, 0, 1); // send garbage
            byte[] reply = new byte[5];
            stream.Read(reply, 0, 5);
            byte[] expected = { 0, 0, 0, 1,
              (byte)Agent.Message.SSH_AGENT_FAILURE };
            Assert.That(reply, Is.EqualTo(expected));
          }
        }

      }
      // check that temporary directory was cleaned up after dispose
      Assert.That(Directory.Exists(socketDir), Is.False,
        "Temporary directory was not deleted");

      // check that environment vars are cleared
      socketPathEnv = Environment
        .GetEnvironmentVariable(UnixAgent.SSH_AUTHSOCKET_ENV_NAME);
      pidEnv = Environment
        .GetEnvironmentVariable(UnixAgent.SSH_AGENTPID_ENV_NAME);
      Assert.That(socketPathEnv, Is.Null,
                    "Failed to unset environment variable " +
        UnixAgent.SSH_AUTHSOCKET_ENV_NAME
      );
      Assert.That(pidEnv, Is.Null,
                    "Failed to unset environment variable " +
        UnixAgent.SSH_AGENTPID_ENV_NAME
      );
    }


    /* helper methods */

    private T GetField<T>(Object instance, string name)
    {
      Type t = instance.GetType();
      FieldInfo f = t.GetField(name, BindingFlags.Instance |
        BindingFlags.NonPublic | BindingFlags.Public
      );

      return (T)f.GetValue(instance);
    }

    private T ExecuteMethod<T>(object instance, String name,
      params object[] paramList)
    {
      Type t = instance.GetType();
      Type[] paramTypes;
      if (paramList != null) {
        paramTypes = new Type[paramList.Length];

        for (int i = 0; i < paramList.Length; i++)
          paramTypes[i] = paramList[i].GetType();
      } else {
        paramTypes = new Type[0];
      }
      MethodInfo m = t.GetMethod(name, BindingFlags.Instance |
        BindingFlags.NonPublic | BindingFlags.Public,
        null, paramTypes, null);

      return (T)m.Invoke(instance, paramList);
    }
  }
}

