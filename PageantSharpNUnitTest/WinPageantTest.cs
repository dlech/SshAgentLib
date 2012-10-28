using dlech.PageantSharp;
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using NUnit.Framework;
using PageantSharpNUnitTest.Properties;
using System.IO;
using System.Threading;
using System.IO.MemoryMappedFiles;

namespace PageantSharpTest
{
  /// <summary>
  ///This is a test class for PageantWindowTest and is intended
  ///to contain all PageantWindowTest Unit Tests
  ///</summary>
  [TestFixture()]
  [Platform(Include = "Win")]
  public class WinPageantTest
  {

    private const int WM_COPYDATA = 0x004A;
    private const long AGENT_COPYDATA_ID = 0x804e50ba;

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg,
      IntPtr wParam, COPYDATASTRUCT lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr FindWindow(String sClassName, String sAppName);

    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT
    {
      public IntPtr dwData;
      public int cbData;
      public IntPtr lpData;
    }


    /// <summary>
    /// Test for WinPagent
    /// </summary>
    [Test()]
    public void WinPageantInstanceTest()
    {
      /* code based on agent_query function in winpgntc.c from PuTTY */
      
      Agent.RemoveAllSSH2KeysCallback removeAllKeys = delegate()
      {
        return true;
      };

      Agent.CallBacks callbacks = new Agent.CallBacks();
      callbacks.removeAllSSH2Keys = removeAllKeys;
      using (WinPageant agent = new WinPageant(callbacks)) {

        /* try starting a second instance */

        Assert.That(delegate()
        {
          WinPageant agent2 = new WinPageant(callbacks);
          agent2.Dispose();
        }, Throws.InstanceOf<PageantRunningException>());

        /* test WndProc callback */

        IntPtr hwnd = FindWindow("Pageant", "Pageant");
        Assert.That(hwnd, Is.Not.EqualTo(IntPtr.Zero));
        int threadId = Thread.CurrentThread.ManagedThreadId;
        string mapName = String.Format("PageantRequest{0:x8}", threadId);
        using (MemoryMappedFile mappedFile = MemoryMappedFile.CreateNew(mapName, 4096)) {
          Assert.That(mappedFile.SafeMemoryMappedFileHandle.IsInvalid, Is.False);
          using (MemoryMappedViewStream stream = mappedFile.CreateViewStream()) {
            byte[] message = new byte[] {0, 0, 0, 1,
            (byte)OpenSsh.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES};
            stream.Write(message, 0, message.Length);
            COPYDATASTRUCT copyData = new COPYDATASTRUCT();
            copyData.dwData = Marshal.AllocCoTaskMem(IntPtr.Size);            
            Marshal.WriteInt64(copyData.dwData, AGENT_COPYDATA_ID);           
            copyData.cbData = mapName.Length + 1;
            copyData.lpData = Marshal.StringToCoTaskMemAnsi(mapName);
            IntPtr resultPtr = SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, copyData);
            int result = Marshal.ReadInt32(resultPtr);
            Assert.That(result, Is.Not.EqualTo(0));
            byte[] reply = new byte[5];
            stream.Position = 0;
            stream.Read(reply, 0, reply.Length);
            byte[] expected = {0, 0, 0, 1, 
                             (byte)OpenSsh.Message.SSH_AGENT_SUCCESS};
            Assert.That(reply, Is.EqualTo(expected));
          }
        }
      }
    }

  }
}
