using System;
using NUnit.Framework;
using dlech.PageantSharp;
using System.Reflection;
using System.IO;
using System.Threading;

namespace PageantSharpTest
{
  [TestFixture()]
  public class LinAgentTest
  {
    /// <summary>
    /// Tests that the temp dir is deleted on Dispose/Finalize.
    /// </summary>
    [Test()]
    public void TestInitAndDispose()
    {
      LinAgent agent = new LinAgent();
      string socketDir = GetField<string>(agent, "socketDir");

      // check that everything was cleaned up after dispose
      agent.Dispose();
      Assert.IsFalse(Directory.Exists(socketDir),
        "Temporary directory was not deleted");
    }

    [Test()]
    public void TestSocket()
    {
      LinAgent agent = new LinAgent();
      while (true) {
        Thread.Sleep(100);
      }
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

