// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2015,2022 David Lechner <david@lechnology.com>

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
        const int WSAECONNRESET = 10054;

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
        WslSocket wslSocket;
        WindowsOpenSshPipe opensshPipe;
        Thread winThread;

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
            [MarshalAs(UnmanagedType.LPWStr)] string lpClassName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpWindowName,
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
            IntPtr hWnd,
            uint msg,
            IntPtr wParam,
            IntPtr lParam
        );

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
            DoOSCheck();

            if (CheckPageantRunning())
            {
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
            if (class_atom == 0 && last_error != ERROR_CLASS_ALREADY_EXISTS)
            {
                throw new Exception("Could not register window class");
            }

            winThread = new Thread(RunWindowInNewAppcontext);
            winThread.SetApartmentState(ApartmentState.STA);
            winThread.Name = "PageantWindow";
            lock (lockObject)
            {
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
            if (disposed)
            {
                throw new ObjectDisposedException("PagentAgent");
            }
            if (cygwinSocket != null)
            {
                return;
            }
            // only overwrite a file if it looks like a CygwinSocket file.
            // TODO: Might be good to test that there are not network sockets using
            // the port specified in this file.
            if (File.Exists(path) && CygwinSocket.TestFile(path))
            {
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
            if (disposed)
            {
                throw new ObjectDisposedException("PagentAgent");
            }
            if (msysSocket != null)
            {
                return;
            }
            // only overwrite a file if it looks like a MsysSocket file.
            // TODO: Might be good to test that there are not network sockets using
            // the port specified in this file.
            if (File.Exists(path) && MsysSocket.TestFile(path))
            {
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

        /// <summary>
        /// Starts a wsl style socket that can be used by the ssh program
        /// that comes with wsl.
        /// </summary>
        /// <param name="path">The path to the socket file that will be created.</param>
        public void StartWslSocket(string path)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("PagentAgent");
            }
            if (wslSocket != null)
            {
                return;
            }
            // only overwrite a file if it looks like a WslSocket file.
            if (File.Exists(path) && WslSocket.TestFile(path))
            {
                File.Delete(path);
            }
            wslSocket = new WslSocket(path, connectionHandler);
        }

        public void StopWslSocket()
        {
            if (disposed)
                throw new ObjectDisposedException("PagentAgent");
            if (wslSocket == null)
                return;
            wslSocket.Dispose();
            wslSocket = null;
        }

        public void StartWindowsOpenSshPipe()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(null);
            }
            if (opensshPipe != null)
            {
                return;
            }
            opensshPipe = new WindowsOpenSshPipe(connectionHandler);
        }

        public void StopWindowsOpenSshPipe()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(null);
            }
            if (opensshPipe == null)
            {
                return;
            }
            opensshPipe.Dispose();
            opensshPipe = null;
        }

        public override void Dispose()
        {
            if (!disposed)
            {
                appContext.ExitThread();
                winThread.Join();
            }
        }

        #endregion


        #region /* private methods */

        private void RunWindowInNewAppcontext()
        {
            IntPtr hwnd;
            lock (lockObject)
            {
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

                appContext = new ApplicationContext();
                Monitor.Pulse(lockObject);
            }
            // Pageant window is run in its own application context so that it does
            // not block the UI thread of applications that use it.
            Application.Run(appContext);

            // make sure socket files are cleaned up when we stop.
            StopCygwinSocket();
            StopMsysSocket();
            StopWslSocket();
            StopWindowsOpenSshPipe();

            if (hwnd != IntPtr.Zero)
            {
                if (DestroyWindow(hwnd))
                {
                    hwnd = IntPtr.Zero;
                    disposed = true;
                }
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
        private IntPtr CustomWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            // we only care about COPYDATA messages
            if (msg != WM_COPYDATA)
            {
                return DefWindowProcW(hWnd, msg, wParam, lParam);
            }

            IntPtr result = IntPtr.Zero;

            // convert lParam to something usable
            COPYDATASTRUCT copyData = (COPYDATASTRUCT)Marshal.PtrToStructure(
                lParam,
                typeof(COPYDATASTRUCT)
            );

            if (
                (
                    (IntPtr.Size == 4)
                    && (copyData.dwData.ToInt32() != (unchecked((int)AGENT_COPYDATA_ID)))
                ) || ((IntPtr.Size == 8) && (copyData.dwData.ToInt64() != AGENT_COPYDATA_ID))
            )
            {
                return result; // failure
            }

            string mapname = Marshal.PtrToStringAnsi(copyData.lpData);
            if (mapname.Length != copyData.cbData - 1)
            {
                return result; // failure
            }

            try
            {
                using (
                    MemoryMappedFile fileMap = MemoryMappedFile.OpenExisting(
                        mapname,
                        MemoryMappedFileRights.FullControl
                    )
                )
                {
                    if (fileMap.SafeMemoryMappedFileHandle.IsInvalid)
                    {
                        return result; // failure
                    }

                    var mapOwner = fileMap.GetAccessControl().GetOwner(typeof(SecurityIdentifier));

                    // check to see if message sender is same user as this program's user
                    // also see http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-backwards-compatibility.html

                    var id = WindowsIdentity.GetCurrent();

                    Process otherProcess = null;
                    try
                    {
                        otherProcess = WinInternals.FindProcessWithMatchingHandle(fileMap);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(ex.ToString());
                    }

                    if (id.User == mapOwner || id.Owner == mapOwner)
                    {
                        using (MemoryMappedViewStream stream = fileMap.CreateViewStream())
                        {
                            AnswerMessage(stream, otherProcess);
                        }
                        result = new IntPtr(1);
                        return result; // success
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.Fail(ex.ToString());
            }
            return result; // failure
        }

        private static void DoOSCheck()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotSupportedException("Pageant requires Windows");
            }
        }

        void connectionHandler(Stream stream, Process process)
        {
            try
            {
                while (true)
                {
                    AnswerMessage(stream, process);
                }
            }
            catch (IOException ex)
            {
                var socketException = ex.InnerException as SocketException;
                if (
                    socketException != null
                    && (
                        socketException.ErrorCode == WSAECONNABORTED
                        || socketException.ErrorCode == WSAECONNRESET
                    )
                )
                {
                    // expected error
                    return;
                }
                if (stream is PipeStream)
                {
                    // broken pipe is expected
                    return;
                }
                throw;
            }
        }

        #endregion
    }
}
