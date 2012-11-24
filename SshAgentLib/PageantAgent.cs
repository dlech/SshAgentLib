using System;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
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
    public PageantAgent()
    {
      if (CheckAlreadyRunning()) {
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

      if (class_atom == 0 && last_error != ERROR_CLASS_ALREADY_EXISTS) {
        throw new Exception("Could not register window class");
      }

      Thread winThread = new Thread(RunWindowInNewAppcontext);
      winThread.SetApartmentState(ApartmentState.STA);
      winThread.Name = "PageantWindow";
      winThread.Start();
      lock (mLockObject) {
        // wait for window to be created before continuing to prevent more than
        // one instance being run at a time.
        Monitor.Wait(mLockObject);
      }
    }

    #endregion


    #region /* public methods */

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
    /// Checks to see if Pageant is already running
    /// </summary>
    /// <returns>true if Pageant is running</returns>
    private bool CheckAlreadyRunning()
    {
      IntPtr hwnd = FindWindow(cClassName, cClassName);
      return (hwnd != IntPtr.Zero);
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

      IntPtr result = Marshal.AllocHGlobal(sizeof(int));
      Marshal.WriteInt32(result, 0); // translation: int result = 0;

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

          // TODO is this sufficient or should we do like Pageant does 
          // and retrieve sid from processes?
          WindowsIdentity user = WindowsIdentity.GetCurrent();
          SecurityIdentifier sid = user.User;

          if (sid == mapOwner) {
            using (MemoryMappedViewStream stream = fileMap.CreateViewStream()) {
              AnswerMessage(stream);
            }
            Marshal.WriteInt32(result, 1);
            return result; // success
          }
        }
      } catch (Exception ex) {
        Debug.Fail(ex.ToString());
      }
      return result; // failure
    }

    #endregion
  }

}
