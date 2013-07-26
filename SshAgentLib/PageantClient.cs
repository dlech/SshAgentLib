//
// PageantClient.cs
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
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Threading;

// code based on agent_query function in winpgntc.c from PuTTY */

namespace dlech.SshAgentLib
{
  public class PageantClient : AgentClient
  {
    public const string cPageantWindowClass = "Pageant";
    public const string cMapNamePrefix = "SshAgentPageantClientRequest";

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

    public override byte[] SendMessage(byte[] aMessage)
    {
      var hwnd = FindWindow(cPageantWindowClass, cPageantWindowClass);
      if (hwnd == IntPtr.Zero) {
        throw new AgentNotRunningException();
      }
      var threadId = Thread.CurrentThread.ManagedThreadId;
      var mapName = String.Format("{0}{1:x8}", cMapNamePrefix, threadId);
      using (var mappedFile = MemoryMappedFile.CreateNew(mapName, 4096)) {
        if (mappedFile.SafeMemoryMappedFileHandle.IsInvalid) {
          throw new Exception("Invalid mapped file handle");
        }
        using (var stream = mappedFile.CreateViewStream()) {
          stream.Write(aMessage, 0, aMessage.Length);
          var copyData = new COPYDATASTRUCT();
          if (IntPtr.Size == 4) {
            copyData.dwData = new IntPtr(unchecked((int)AGENT_COPYDATA_ID));
          } else {
            copyData.dwData = new IntPtr(AGENT_COPYDATA_ID);
          }
          copyData.cbData = mapName.Length + 1;
          copyData.lpData = Marshal.StringToCoTaskMemAnsi(mapName);
          var copyDataGCHandle = GCHandle.Alloc(copyData, GCHandleType.Pinned);
          var copyDataPtr = copyDataGCHandle.AddrOfPinnedObject();
          var resultPtr =
            SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, copyDataPtr);
          copyDataGCHandle.Free();          
          if (resultPtr == IntPtr.Zero) {
            throw new Exception("send message failed");
          }
          stream.Position = 0;
          var parser = new BlobParser(stream);
          var replyLength = parser.ReadInt();
          stream.Position = 0;
          var reply = new byte[replyLength + 4];
          stream.Read(reply, 0, reply.Length);
          return reply;
        }
      }
    }
  }
}