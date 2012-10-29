using System;
using NUnit.Framework;
using dlech.PageantSharp;
using System.Reflection;
using System.IO;
using System.Threading;
using Mono.Unix;
using System.Net.Sockets;

namespace PageantSharpTest
{
  [TestFixture()]
  [Platform(Exclude="Win")]
  public class LinAgentTest
  {
    /// <summary>
    /// Tests that the temp dir is deleted on Dispose/Finalize.
    /// </summary>
    [Test()]
    public void TestLinAgent()
    {
      string socketDir;
      string socketPathEnv;
      string pidEnv;
      Agent.Callbacks callbacks = new Agent.Callbacks();
      using (LinAgent agent = new LinAgent(callbacks)) {
        socketDir = GetField<string>(agent, "socketDir");
        int pid = UnixProcess.GetCurrentProcessId();
        socketPathEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME);
        pidEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AGENTPID_ENV_NAME);

        Assert.That(socketPathEnv.Contains(socketDir), Is.True,
          "Failed to set environment variable " +
          LinAgent.SSH_AUTHSOCKET_ENV_NAME
        );
        Assert.That(pidEnv, Is.EqualTo(pid.ToString()),
          "Failed to set environment variable " +
          LinAgent.SSH_AGENTPID_ENV_NAME
        );
                
        using (UnixClient client = new UnixClient (socketPathEnv)) {
          using (NetworkStream stream = client.GetStream ()) {
            stream.Write(new byte[] { 0 }, 0, 1); // send garbage
            byte[] reply = new byte[5];
            stream.Read(reply, 0, 5);
            byte[] expected = { 0, 0, 0, 1,
              (byte)OpenSsh.Message.SSH_AGENT_FAILURE };
            Assert.That(reply, Is.EqualTo(expected));
          }
        }

      }
      // check that temporary directory was cleaned up after dispose
      Assert.That(Directory.Exists(socketDir), Is.False,
        "Temporary directory was not deleted");

      // check that environment vars are cleared
      socketPathEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME);
      pidEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AGENTPID_ENV_NAME);
      Assert.That(socketPathEnv, Is.Null,
                    "Failed to unset environment variable " +
        LinAgent.SSH_AUTHSOCKET_ENV_NAME
      );
      Assert.That(pidEnv, Is.Null,
                    "Failed to unset environment variable " +
        LinAgent.SSH_AGENTPID_ENV_NAME
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

