#if !__MonoCS__
#define NotMono
#endif

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
#if NotMono
  [Ignore("Not Mono")]
#endif
  public class LinAgentTest
  {
    /// <summary>
    /// Tests that the temp dir is deleted on Dispose/Finalize.
    /// </summary>
    [Test()]
    public void TestInitAndDispose()
    {
      Agent.CallBacks callbacks = new Agent.CallBacks();
      LinAgent agent = new LinAgent(callbacks);
      string socketDir = GetField<string>(agent, "socketDir");
      int pid = UnixProcess.GetCurrentProcessId();
      string socketPathEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME);
      string pidEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AGENTPID_ENV_NAME);

      Assert.IsTrue(socketPathEnv.Contains(socketDir),
                    "Failed to set environment variable " +
                    LinAgent.SSH_AUTHSOCKET_ENV_NAME);
      Assert.AreEqual(pid.ToString(), pidEnv,
                      "Failed to set environment variable " +
                      LinAgent.SSH_AGENTPID_ENV_NAME);

      // check that temporary directory was cleaned up after dispose
      agent.Dispose();
      Assert.IsFalse(Directory.Exists(socketDir),
        "Temporary directory was not deleted");

      // check that environment vars are cleared
      socketPathEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME);
      pidEnv = Environment
        .GetEnvironmentVariable(LinAgent.SSH_AGENTPID_ENV_NAME);
      Assert.IsNull(socketPathEnv,
                    "Failed to unset environment variable " +
                    LinAgent.SSH_AUTHSOCKET_ENV_NAME);
      Assert.IsNull(pidEnv,
                    "Failed to unset environment variable " +
                    LinAgent.SSH_AGENTPID_ENV_NAME);
    }

    [Test()]
    public void TestSocket()
    {
      Agent.CallBacks callbacks = new Agent.CallBacks();
      LinAgent agent = new LinAgent(callbacks);
      string socketPath = Environment.GetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME);

      UnixClient client = new UnixClient(socketPath);
      NetworkStream stream = client.GetStream();
      stream.Write(new byte[] { 0 }, 0, 1); // send garbage
      byte[] reply = new byte[5];
      stream.Read(reply, 0, 5);
      Assert.AreEqual(0, reply[0]);
      Assert.AreEqual(0, reply[1]);
      Assert.AreEqual(0, reply[2]);
      Assert.AreEqual(1, reply[3]);
      Assert.AreEqual(5, reply[4]); // 5 = bad request
      agent.Dispose();
    }



    /* helper methods */

    private T GetField<T>(Object instance, string name)
    {
      Type t = instance.GetType();
      FieldInfo f = t.GetField(name, BindingFlags.Instance |
        BindingFlags.NonPublic | BindingFlags.Public);

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

