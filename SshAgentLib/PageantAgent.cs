using System;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using System.Management;


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

    private const int ERROR_CLASS_ALREADY_EXISTS = 1410;
    private const int WM_COPYDATA = 0x004A;

    /* From PuTTY source code */

    private const string cClassName = "Pageant";
    private const long AGENT_COPYDATA_ID = 0x804e50ba;

    #endregion


    #region /* instance variables */

    private bool mDisposed;
    private WndProc mCustomWndProc;
    private ApplicationContext mAppContext;
    private object mLockObject = new object();

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
    public PageantAgent ()
    {
      DoOSCheck();

      if (CheckPageantRunning()) {
        throw new PageantRunningException();
      }

      // create reference to delegate so that garbage collector does not eat it.
      mCustomWndProc = new WndProc(CustomWndProc);

      // Create WNDCLASS
      WNDCLASS wind_class = new WNDCLASS();
      wind_class.lpszClassName = cClassName;
      wind_class.lpfnWndProc = mCustomWndProc;

      UInt16 class_atom = RegisterClassW(ref wind_class);

      int last_error = Marshal.GetLastWin32Error();
      if (class_atom == 0 && last_error == ERROR_CLASS_ALREADY_EXISTS) {
        Debug.Fail("Pageant window class already exists");
      }
      if (class_atom == 0 && last_error != ERROR_CLASS_ALREADY_EXISTS) {
        throw new Exception("Could not register window class");
      }

      Thread winThread = new Thread(RunWindowInNewAppcontext);
      winThread.SetApartmentState(ApartmentState.STA);
      winThread.Name = "PageantWindow";
      lock (mLockObject) {
        winThread.Start();
        // wait for window to be created before continuing to prevent more than
        // one instance being run at a time.
        if (!Monitor.Wait(mLockObject, 5000))
        {
          if (winThread.ThreadState == System.Threading.ThreadState.Running)
          {
            MessageBox.Show("Pageant Agent start timed out.");
          }
          else
          {
            MessageBox.Show("Pageant Agent failed to start.");
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
      IntPtr hwnd = FindWindow(cClassName, cClassName);
      return (hwnd != IntPtr.Zero);
    }


    public override void Dispose()
    {
      Dispose(true);
      GC.SuppressFinalize(this);
    }

    #endregion


    #region /* private methods */

    private void RunWindowInNewAppcontext()
    {
      IntPtr hwnd;
      lock (mLockObject) {
        // Create window
        hwnd = CreateWindowExW(
            0, // dwExStyle
            cClassName, // lpClassName
            cClassName, // lpWindowName
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

        mAppContext = new ApplicationContext();
        Monitor.Pulse(mLockObject);
      }
      // Pageant window is run in its own application context so that it does
      // not block the UI thread of applications that use it.
      Application.Run(mAppContext);
      if (hwnd != IntPtr.Zero) {
        if (DestroyWindow(hwnd)) {
          hwnd = IntPtr.Zero;
          mDisposed = true;
        }
      }
    }

    private void Dispose(bool aDisposing)
    {
      if (!mDisposed) {
        if (aDisposing) {
          // Dispose managed resources
        }
        mAppContext.ExitThread();
        // Dispose unmanaged resources 
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

          if (userSid == mapOwner || procOwnerSid == mapOwner) {
            using (MemoryMappedViewStream stream = fileMap.CreateViewStream()) {
              AnswerMessage(stream);
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
