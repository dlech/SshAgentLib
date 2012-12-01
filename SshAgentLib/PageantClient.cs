using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO.MemoryMappedFiles;

/* code based on agent_query function in winpgntc.c from PuTTY */

namespace dlech.SshAgentLib
{
  public class PageantClient : AgentClient
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

    public override void SendMessage(byte[] aMessage, out byte[] aReply)
    {
      var hwnd = FindWindow("Pageant", "Pageant");
      if (hwnd == IntPtr.Zero) {
        throw new Exception("Pageant not found");
      }
      var threadId = Thread.CurrentThread.ManagedThreadId;
      var mapName = String.Format("PageantRequest{0:x8}", threadId);
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
          var resultPtr = SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, copyDataPtr);
          copyDataGCHandle.Free();          
          if (resultPtr == IntPtr.Zero) {
            throw new Exception("send message failed");
          }
          stream.Position = 0;
          var parser = new BlobParser(stream);
          var replyLength = parser.ReadInt();
          stream.Position = 0;
          aReply = new byte[replyLength + 4];
          stream.Read(aReply, 0, aReply.Length);
        }
      }
    }
  }
}