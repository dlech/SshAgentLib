using dlech.SshAgentLib;
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
using dlech.SshAgentLibTests.Properties;
using System.IO;
using System.Threading;
using System.IO.MemoryMappedFiles;

namespace dlech.SshAgentLibTests
{
  /// <summary>
  ///This is a test class for PageantWindowTest and is intended
  ///to contain all PageantWindowTest Unit Tests
  ///</summary>
  [TestFixture()]
  [Platform(Include = "Win")]
  public class PageantAgentTest
  {

    private const int WM_COPYDATA = 0x004A;
    private const long AGENT_COPYDATA_ID = 0x804e50ba;

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg,
      IntPtr wParam, IntPtr lParam);

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
    public void PageantAgentInstanceTest()
    {
      /* code based on agent_query function in winpgntc.c from PuTTY */

      using (PageantAgent agent = new PageantAgent()) {
                
        /* try starting a second instance */

        Assert.That(delegate()
        {
          PageantAgent agent2 = new PageantAgent();
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
            (byte)Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES};
            stream.Write(message, 0, message.Length);
            COPYDATASTRUCT copyData = new COPYDATASTRUCT();
            if (IntPtr.Size == 4) {
              copyData.dwData = new IntPtr(unchecked((int)AGENT_COPYDATA_ID));
            } else {
              copyData.dwData = new IntPtr(AGENT_COPYDATA_ID);
            }
            copyData.cbData = mapName.Length + 1;
            copyData.lpData = Marshal.StringToCoTaskMemAnsi(mapName);
            GCHandle copyDataGCHandle = GCHandle.Alloc(copyData, GCHandleType.Pinned);
            IntPtr copyDataPtr = copyDataGCHandle.AddrOfPinnedObject();
            IntPtr resultPtr = SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, copyDataPtr);
            copyDataGCHandle.Free();
            int result = Marshal.ReadInt32(resultPtr);
            Assert.That(result, Is.Not.EqualTo(0));
            byte[] reply = new byte[5];
            stream.Position = 0;
            stream.Read(reply, 0, reply.Length);
            byte[] expected = {0, 0, 0, 1,
                               (byte)Agent.Message.SSH_AGENT_SUCCESS};
            Assert.That(reply, Is.EqualTo(expected));
          }
        }
      }
    }

  }
}
