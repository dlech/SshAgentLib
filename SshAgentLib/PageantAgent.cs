//
// PageantAgent.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2015 David Lechner
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
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace dlech.SshAgentLib
{
  // Code based on http://stackoverflow.com/questions/128561/registering-a-custom-win32-window-class-from-c-sharp
  // and Putty source code http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html

  /// <summary>
  /// Creates a window using Windows API calls so that we can register the class
  /// of the window. This is how putty "talks" to pageant. This window will not
  /// actually be shown, just used to receive messages from clients.
  /// </summary>
  public class PageantAgent : Agent
  {
    #region /* constants */

    /* From WINAPI */

    const int ERROR_CLASS_ALREADY_EXISTS = 1410;
    const int WM_COPYDATA = 0x004A;
    const int WSAECONNABORTED = 10053;
    
    enum MessageFilterInfo : uint
    {
        None=0, AlreadyAllowed=1, AlreadyDisAllowed=2, AllowedHigher=3
    };

    enum ChangeWindowMessageFilterExAction : uint
    {
        Reset = 0, Allow = 1, DisAllow = 2
    };

    [StructLayout(LayoutKind.Sequential)]
    struct CHANGEFILTERSTRUCT
    {
        public uint size;
        public MessageFilterInfo info;
    }

    /* From PuTTY source code */

    const string className = "Pageant";
    const long AGENT_COPYDATA_ID = 0x804e50ba;

    #endregion


    #region /* instance variables */

    bool disposed;
    WndProc customWndProc;
    ApplicationContext appContext;
    object lockObject = new object();
    CygwinSocket cygwinSocket;
    MsysSocket msysSocket;
    WindowsOpenSshPipe opensshPipe;

    #endregion


    #region /* delegates */

    private delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    #endregion


    #region /* structs */

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASS
    {
      public uint style;
      public WndProc lpfnWndProc;
      public int cbClsExtra;
      public int cbWndExtra;
      public IntPtr hInstance;
      public IntPtr hIcon;
      public IntPtr hCursor;
      public IntPtr hbrBackground;
      [MarshalAs(UnmanagedType.LPWStr)]
      public string lpszMenuName;
      [MarshalAs(UnmanagedType.LPWStr)]
      public string lpszClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT
    {
      public IntPtr dwData;
      public int cbData;
      public IntPtr lpData;
    }

    #endregion


    #region /* externs */

    [DllImport("user32.dll")]
    private static extern IntPtr FindWindow(String sClassName, String sAppName);

    /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms633586%28v=vs.85%29.aspx
    [DllImport("user32.dll", SetLastError = true)]
    private static extern System.UInt16 RegisterClassW([In] ref WNDCLASS lpWndClass);

    /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms632680%28v=vs.85%29.aspx
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreateWindowExW(
       UInt32 dwExStyle,
       [MarshalAs(UnmanagedType.LPWStr)]
       string lpClassName,
       [MarshalAs(UnmanagedType.LPWStr)]
       string lpWindowName,
       UInt32 dwStyle,
       Int32 x,
       Int32 y,
       Int32 nWidth,
       Int32 nHeight,
       IntPtr hWndParent,
       IntPtr hMenu,
       IntPtr hInstance,
       IntPtr lpParam
    );

    [DllImport("user32.dll", SetLastError = true)]
    private static extern System.IntPtr DefWindowProcW(
        IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, uint message, ChangeWindowMessageFilterExAction action, [In, Out, Optional] ref CHANGEFILTERSTRUCT changeInfo);

    #endregion


    #region /* constructors */

    /// <summary>
    /// Creates a new instance of PageantWindow that acts as a server for
    /// Putty-type clients.    
    /// </summary>
    /// <exception cref="PageantRunningException">
    /// Thrown when another instance of Pageant is running.
    /// </exception>
    /// <remarks>This window is not meant to be used for UI.</remarks>
    public PageantAgent (bool AllowAccessFromNonElevatedProcess)
    {
      DoOSCheck();

      if (CheckPageantRunning()) {
        throw new PageantRunningException();
      }

      // create reference to delegate so that garbage collector does not eat it.
      customWndProc = new WndProc(CustomWndProc);

      // Create WNDCLASS
      WNDCLASS wind_class = new WNDCLASS();
      wind_class.lpszClassName = className;
      wind_class.lpfnWndProc = customWndProc;

      UInt16 class_atom = RegisterClassW(ref wind_class);

      int last_error = Marshal.GetLastWin32Error();
      if (class_atom == 0 && last_error != ERROR_CLASS_ALREADY_EXISTS) {
        throw new Exception("Could not register window class");
      }

      Thread winThread = new Thread(() => RunWindowInNewAppcontext(AllowAccessFromNonElevatedProcess));
      winThread.SetApartmentState(ApartmentState.STA);
      winThread.Name = "PageantWindow";
      lock (lockObject) {
        winThread.Start();
        // wait for window to be created before continuing to prevent more than
        // one instance being run at a time.
        if (!Monitor.Wait(lockObject, 5000))
        {
          if (winThread.ThreadState == System.Threading.ThreadState.Running)
          {
            throw new TimeoutException("PageantAgent start timed out.");
          }
          else
          {
            throw new Exception("PageantAgent failed to start.");
          }
        }
      }
    }

    #endregion


    #region /* public methods */

    /// <summary>
    /// Checks to see if any Pageant-like application is running
    /// </summary>
    /// <returns>true if Pageant is running</returns>
    public static bool CheckPageantRunning()
    {
      DoOSCheck();
      IntPtr hwnd = FindWindow(className, className);
      return (hwnd != IntPtr.Zero);
    }

    /// <summary>
    /// Starts a cygwin style socket that can be used by the ssh program
    /// that comes with cygwin.
    /// </summary>
    /// <param name="path">The path to the socket file that will be created.</param>
    public void StartCygwinSocket(string path)
    {
      if (disposed) {
        throw new ObjectDisposedException("PagentAgent");
      }
      if (cygwinSocket != null) {
        return;
      }
      // only overwrite a file if it looks like a CygwinSocket file.
      // TODO: Might be good to test that there are not network sockets using
      // the port specified in this file.
      if (File.Exists(path) && CygwinSocket.TestFile(path)) {
        File.Delete(path);
      }
      cygwinSocket = new CygwinSocket(path);
      cygwinSocket.ConnectionHandler = connectionHandler;
    }

    public void StopCygwinSocket()
    {
      if (disposed)
        throw new ObjectDisposedException("PagentAgent");
      if (cygwinSocket == null)
        return;
      cygwinSocket.Dispose();
      cygwinSocket = null;
    }

    /// <summary>
    /// Starts a msysgit style socket that can be used by the ssh program
    /// that comes with msysgit.
    /// </summary>
    /// <param name="path">The path to the socket file that will be created.</param>
    public void StartMsysSocket(string path)
    {
      if (disposed) {
        throw new ObjectDisposedException("PagentAgent");
      }
      if (msysSocket != null) {
        return;
      }
      // only overwrite a file if it looks like a MsysSocket file.
      // TODO: Might be good to test that there are not network sockets using
      // the port specified in this file.
      if (File.Exists(path) && MsysSocket.TestFile(path)) {
        File.Delete(path);
      }
      msysSocket = new MsysSocket(path);
      msysSocket.ConnectionHandler = connectionHandler;
    }

    public void StopMsysSocket()
    {
      if (disposed)
        throw new ObjectDisposedException("PagentAgent");
      if (msysSocket == null)
        return;
      msysSocket.Dispose();
      msysSocket = null;
    }

    public void StartWindowsOpenSshPipe()
    {
      if (disposed) {
        throw new ObjectDisposedException(null);
      }
      if (opensshPipe != null) {
        return;
      }
      opensshPipe = new WindowsOpenSshPipe();
      opensshPipe.ConnectionHandler = connectionHandler;
    }

    public void StopWindowsOpenSshPipe()
    {
      if (disposed) {
        throw new ObjectDisposedException(null);
      }
      if (opensshPipe == null) {
        return;
      }
      opensshPipe.Dispose();
      opensshPipe = null;
    }

    public override void Dispose()
    {
      Dispose(true);
      GC.SuppressFinalize(this);
    }

    #endregion


    #region /* private methods */

    private void RunWindowInNewAppcontext(bool AllowAccessFromNonElevatedProcess)
    {
      IntPtr hwnd;
      lock (lockObject) {
        // Create window
        hwnd = CreateWindowExW(
            0, // dwExStyle
            className, // lpClassName
            className, // lpWindowName
            0, // dwStyle
            0, // x
            0, // y
            0, // nWidth
            0, // nHeight
            IntPtr.Zero, // hWndParent
            IntPtr.Zero, // hMenu
            IntPtr.Zero, // hInstance
            IntPtr.Zero // lpParam
        );

        if (AllowAccessFromNonElevatedProcess)
        {
            CHANGEFILTERSTRUCT filterStatus = new CHANGEFILTERSTRUCT();
            filterStatus.size = (uint)Marshal.SizeOf(filterStatus);
            bool b = ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, ChangeWindowMessageFilterExAction.Allow, ref filterStatus);
        }

        appContext = new ApplicationContext();
        Monitor.Pulse(lockObject);
      }
      // Pageant window is run in its own application context so that it does
      // not block the UI thread of applications that use it.
      Application.Run(appContext);

      // make sure socket files are cleaned up when we stop.
      StopCygwinSocket();
      StopMsysSocket();
      StopWindowsOpenSshPipe();

      if (hwnd != IntPtr.Zero) {
        if (DestroyWindow(hwnd)) {
          hwnd = IntPtr.Zero;
          disposed = true;
        }
      }
    }

    private void Dispose(bool disposing)
    {
      if (!disposed) {
        appContext.ExitThread();
      }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="hWnd"></param>
    /// <param name="msg"></param>
    /// <param name="wParam"></param>
    /// <param name="lParam"></param>
    /// <returns></returns>
    private IntPtr CustomWndProc(IntPtr hWnd, uint msg, IntPtr wParam,
      IntPtr lParam)
    {
      // we only care about COPYDATA messages
      if (msg != WM_COPYDATA) {
        return DefWindowProcW(hWnd, msg, wParam, lParam);
      }

      IntPtr result = IntPtr.Zero;

      // convert lParam to something usable
      COPYDATASTRUCT copyData = (COPYDATASTRUCT)
        Marshal.PtrToStructure(lParam, typeof(COPYDATASTRUCT));

      if (((IntPtr.Size == 4) &&
           (copyData.dwData.ToInt32() != (unchecked((int)AGENT_COPYDATA_ID)))) ||
          ((IntPtr.Size == 8) &&
           (copyData.dwData.ToInt64() != AGENT_COPYDATA_ID))) {
        return result; // failure
      }

      string mapname = Marshal.PtrToStringAnsi(copyData.lpData);
      if (mapname.Length != copyData.cbData - 1) {
        return result; // failure
      }

      try {
        using (MemoryMappedFile fileMap =
          MemoryMappedFile.OpenExisting(mapname,
          MemoryMappedFileRights.FullControl)) {

          if (fileMap.SafeMemoryMappedFileHandle.IsInvalid) {
            return result; // failure
          }

          SecurityIdentifier mapOwner =
            (SecurityIdentifier)fileMap.GetAccessControl()
            .GetOwner(typeof(System.Security.Principal.SecurityIdentifier));

          /* check to see if message sender is same user as this program's
           * user */

          var user = WindowsIdentity.GetCurrent();
          var userSid = user.User;

          // see http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-backwards-compatibility.html
          var procOwnerSid = GetProcessOwnerSID(Process.GetCurrentProcess().Id);

          Process otherProcess = null;
          try {
              otherProcess = WinInternals.FindProcessWithMatchingHandle(fileMap);
          } catch (Exception ex) {
              Debug.Fail(ex.ToString());
          }

          if (userSid == mapOwner || procOwnerSid == mapOwner) {
            using (MemoryMappedViewStream stream = fileMap.CreateViewStream()) {
              AnswerMessage(stream, otherProcess);
            }
            result = new IntPtr(1);
            return result; // success
          }
        }
      } catch (Exception ex) {
        Debug.Fail(ex.ToString());
      }
      return result; // failure
    }

    private static void DoOSCheck ()
    {
      if (Environment.OSVersion.Platform != PlatformID.Win32NT) {
        throw new NotSupportedException ("Pageant requires Windows");
      }
    }

    void connectionHandler(Stream stream, Process process)
    {
      try {
          while (true) {
              AnswerMessage(stream, process);
          }
      } catch (IOException ex) {
        var socketException = ex.InnerException as SocketException;
        if (socketException != null && socketException.ErrorCode == WSAECONNABORTED) {
          // expected error
          return;
        }
        if (stream is PipeStream) {
          // broken pipe is expected
          return;
        }
        throw;
      }
    }

    [Flags()]
    private enum AccessRights : long
    {
      DELETE = 0x00010000L,
      READ_CONTROL = 0x00020000L,
      WRITE_DAC = 0x00040000L,
      WRITE_OWNER = 0x00080000L,
      SYNCHRONIZE = 0x00100000L,

      STANDARD_RIGHTS_REQUIRED = 0x000F0000L,

      STANDARD_RIGHTS_READ = READ_CONTROL,
      STANDARD_RIGHTS_WRITE = READ_CONTROL,
      STANDARD_RIGHTS_EXECUTE = READ_CONTROL,

      STANDARD_RIGHTS_ALL = 0x001F0000L,

      SPECIFIC_RIGHTS_ALL = 0x0000FFFFL,

      // AccessSystemAcl access type
      ACCESS_SYSTEM_SECURITY = 0x01000000L,

      // MaximumAllowed access type
      MAXIMUM_ALLOWED = 0x02000000L,

      // These are the generic rights.
      GENERIC_READ = 0x80000000L,
      GENERIC_WRITE = 0x40000000L,
      GENERIC_EXECUTE = 0x20000000L,
      GENERIC_ALL = 0x10000000L
    }

    private enum SE_OBJECT_TYPE
    {
      SE_UNKNOWN_OBJECT_TYPE = 0,
      SE_FILE_OBJECT,
      SE_SERVICE,
      SE_PRINTER,
      SE_REGISTRY_KEY,
      SE_LMSHARE,
      SE_KERNEL_OBJECT,
      SE_WINDOW_OBJECT,
      SE_DS_OBJECT,
      SE_DS_OBJECT_ALL,
      SE_PROVIDER_DEFINED_OBJECT,
      SE_WMIGUID_OBJECT,
      SE_REGISTRY_WOW64_32KEY
    }

    [Flags()]
    private enum SECURITY_INFORMATION : long
    {
      OWNER_SECURITY_INFORMATION = 0x00000001L,
      GROUP_SECURITY_INFORMATION = 0x00000002L,
      DACL_SECURITY_INFORMATION = 0x00000004L,
      SACL_SECURITY_INFORMATION = 0x00000008L,
      LABEL_SECURITY_INFORMATION = 0x00000010L,

      PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000L,
      PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000L,
      UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000L,
      UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000L
    }

    [DllImport("kernel32")]
    private static extern IntPtr OpenProcess(AccessRights dwDesiredAccess,
      bool bInheritHandle, long dwProcessId);

    [DllImport("Advapi32")]
    private static extern long GetSecurityInfo(IntPtr handle, 
      SE_OBJECT_TYPE objectType, SECURITY_INFORMATION securityInfo,
      out IntPtr ppsidOwner, out IntPtr ppsidGroup, out IntPtr ppDacl,
      out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

    [DllImport("kernel32")]
    private static extern bool CloseHandle(IntPtr hObject);

    private SecurityIdentifier GetProcessOwnerSID(int pid)
    {
      var processHandle = OpenProcess(AccessRights.MAXIMUM_ALLOWED, false, pid);
      if (processHandle == IntPtr.Zero) {
        return null;
      }
      try {
        IntPtr sidOwner, sidGroup, dacl, sacl, securityDescriptor;

        if (GetSecurityInfo(processHandle, SE_OBJECT_TYPE.SE_KERNEL_OBJECT,
            SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION, out sidOwner,
            out sidGroup, out dacl, out sacl, out securityDescriptor) != 0) {
          return null;
        }
        return new SecurityIdentifier(sidOwner);
      } finally {
        CloseHandle(processHandle);
      }
    }

    #endregion
  }

}
