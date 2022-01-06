//
// PageantAgentTest.cs
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

using dlech.SshAgentLib;
using System;
using System.Runtime.InteropServices;
using NUnit.Framework;
using System.Threading;
using System.IO.MemoryMappedFiles;

namespace dlech.SshAgentLibTests
{
  /// <summary>
  ///This is a test class for PageantWindowTest and is intended
  ///to contain all PageantWindowTest Unit Tests
  ///</summary>
  [TestFixture, NonParallelizable]
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
    [Test, NonParallelizable]
    public void PageantAgentInstanceTest()
    {
      /* code based on agent_query function in winpgntc.c from PuTTY */

      using (PageantAgent agent = new PageantAgent()) {

        /* try starting a second instance */

        Assert.That(delegate()
        {
          using (PageantAgent agent2 = new PageantAgent()) { }
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
            IntPtr copyDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(copyData));
            Marshal.StructureToPtr(copyData, copyDataPtr, false);
            IntPtr resultPtr = SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, copyDataPtr);
            Marshal.FreeCoTaskMem(copyData.lpData);
            Marshal.FreeHGlobal(copyDataPtr);
            Assert.That(resultPtr, Is.Not.EqualTo(IntPtr.Zero));
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
