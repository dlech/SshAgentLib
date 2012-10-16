using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Security.Principal;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Text;
using System.Runtime.ConstrainedExecution;
#if !DOT_NET_35
using System.IO.MemoryMappedFiles;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1;
#endif // DOT_NET_35


namespace dlech.PageantSharp
{
	/// <summary>
	/// Creates a window using Windows API calls so that we can register the class of the window
	/// This is how putty "talks" to pageant.
	/// This window will not actually be shown, just used to receive messages from clients.
	/// 
	/// Code based on http://stackoverflow.com/questions/128561/registering-a-custom-win32-window-class-from-c-sharp
	/// and Putty source code http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html
	/// </summary>
	public class WinPageant : IDisposable
	{
		#region /* constants */

		/* From WINAPI */

		private const int ERROR_CLASS_ALREADY_EXISTS =       1410;
		private const int WM_COPYDATA =                      0x004A;

#if DOT_NET_35
		private const int STANDARD_RIGHTS_REQUIRED =         0x000F0000;
		private const int SECTION_QUERY =                    0x0001;
		private const int SECTION_MAP_WRITE =                0x0002;
		private const int SECTION_MAP_READ =                 0x0004;
		private const int SECTION_MAP_EXECUTE =              0x0008;
		private const int SECTION_EXTEND_SIZE =              0x0010;
		private const int SECTION_MAP_EXECUTE_EXPLICIT =     0x0020; // not included in SECTION_ALL_ACCESS

		private const int SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE |
														 SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE);

		private const int FILE_MAP_ALL_ACCESS =		      		SECTION_ALL_ACCESS;
		private const int FILE_MAP_WRITE =								  SECTION_MAP_WRITE;

		private const int INVALID_HANDLE_VALUE =						-1;
		private const int SE_KERNEL_OBJECT =								6;
		private const int OWNER_SECURITY_INFORMATION =      0x00000001;
		private const int ERROR_SUCCESS =										0;
#endif // DOT_NET_35


		/* From PuTTY source code */

		private const string className = "Pageant";

		private const long AGENT_COPYDATA_ID = 0x804e50ba;



#if DOT_NET_35
		private const int AGENT_MAX_MSGLEN =											8192;
#endif // DOT_NET_35

		#endregion


		#region /* global variables */

		private bool disposed;
		private IntPtr hwnd;
		private WndProc customWndProc;

		Agent.GetSSH2KeyListCallback getSSH2PublicKeyListCallback;
		Agent.GetSSH2KeyCallback getSSH2PublicKeyCallback;


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
		struct COPYDATASTRUCT
		{
			public IntPtr dwData;
			public int cbData;
			public IntPtr lpData;
		}

#if DOT_NET_35

#endif // DOT_NET_35

		#endregion


		#region /* externs */

		[DllImport("user32.dll")]
		public static extern IntPtr FindWindow(String sClassName, String sAppName);

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
		static extern System.IntPtr DefWindowProcW(
				IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

		[DllImport("user32.dll", SetLastError = true)]
		static extern bool DestroyWindow(IntPtr hWnd);

#if DOT_NET_35
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern IntPtr MapViewOfFile(IntPtr hFileMapping, int dwDesiredAccess, int dwFileOffsetHigh, int dwFileOffsetLow, int dwNumberOfBytesToMap);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern IntPtr OpenFileMapping(int dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern int GetSecurityInfo(IntPtr handle, int objectType, int securityInfo,
			out IntPtr ppsidOwner, out IntPtr ppsidGroup, out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr LocalFree(IntPtr hMem);

		[return: MarshalAs(UnmanagedType.Bool)]
		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success), DllImport("Kernel32", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool UnmapViewOfFile(IntPtr pvBaseAddress);
#endif // DOT_NET_35

		#endregion


		#region /* constructors */

		/// <summary>
		/// Creates a new instance of PageantWindow. This window is not meant to be used for UI.
		/// 
		/// </summary>
		/// <exception cref="PageantException">Thrown when another instance of Pageant is running.</exception>
		public WinPageant(Agent.GetSSH2KeyListCallback getSSH2KeyListCallback,
                      Agent.GetSSH2KeyCallback getSS2KeyCallback)
		{
			if (CheckAlreadyRunning()) {
				throw new PageantException();
			}

			/* assign callbacks */
			this.getSSH2PublicKeyListCallback = getSSH2KeyListCallback;
			this.getSSH2PublicKeyCallback = getSS2KeyCallback;

			// create reference to delegate so that garbage collector does not eat it.
			this.customWndProc = new WndProc(CustomWndProc);

			// Create WNDCLASS
			WNDCLASS wind_class = new WNDCLASS();
			wind_class.lpszClassName = WinPageant.className;
			wind_class.lpfnWndProc = this.customWndProc;

			UInt16 class_atom = RegisterClassW(ref wind_class);

			int last_error = Marshal.GetLastWin32Error();

			// TODO do we really need to worry about an error when registering class?
			if (class_atom == 0 && last_error != WinPageant.ERROR_CLASS_ALREADY_EXISTS) {
				throw new System.Exception("Could not register window class");
			}      

			// Create window
			this.hwnd = CreateWindowExW(
					0, // dwExStyle
					WinPageant.className, // lpClassName
					WinPageant.className, // lpWindowName
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
		}

		#endregion


		#region /* public methods */

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		#endregion


		#region /* private methods */

		private void Dispose(bool disposing)
		{
			if (!this.disposed) {
				if (disposing) {
					// Dispose managed resources
				}

				// Dispose unmanaged resources
				if (this.hwnd != IntPtr.Zero) {
					if (DestroyWindow(this.hwnd)) {
						this.hwnd = IntPtr.Zero;
						this.disposed = true;
					}
				}
			}
		}

		/// <summary>
		/// Checks to see if Pageant is already running
		/// </summary>
		/// <returns>true if Pageant is running</returns>
		private bool CheckAlreadyRunning()
		{
			IntPtr hwnd = FindWindow(WinPageant.className, WinPageant.className);
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
		private IntPtr CustomWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
		{
			// we only care about COPYDATA messages
			if (msg == WM_COPYDATA) {
				IntPtr result = Marshal.AllocHGlobal(sizeof(int));
				Marshal.WriteInt32(result, 0); // translation: int result = 0;
        
				// convert lParam to something usable
				COPYDATASTRUCT copyData = (COPYDATASTRUCT)Marshal.PtrToStructure(lParam, typeof(COPYDATASTRUCT));
				// have to handle comparison differently depending on 32 or 64bit architecture
				if (((IntPtr.Size == 4) && (copyData.dwData.ToInt32() == (unchecked ((int)AGENT_COPYDATA_ID)))) ||
					((IntPtr.Size == 8) && (copyData.dwData.ToInt64() == AGENT_COPYDATA_ID))) {

					string mapname = Marshal.PtrToStringAnsi(copyData.lpData);
					if (mapname.Length == copyData.cbData - 1) {
						try {
#if DOT_NET_35
							IntPtr fileMap = OpenFileMapping(FILE_MAP_ALL_ACCESS, false, mapname);

							if (fileMap != IntPtr.Zero && fileMap != new IntPtr(INVALID_HANDLE_VALUE)) {
								IntPtr mapOwnerPtr, group, dacl, sacl; 
								IntPtr securityDescriptorPtr = IntPtr.Zero;								
								if (GetSecurityInfo(fileMap, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
									out mapOwnerPtr, out group, out dacl, out sacl, out securityDescriptorPtr) == ERROR_SUCCESS) {
									SecurityIdentifier mapOwner = new SecurityIdentifier(mapOwnerPtr);
									LocalFree(securityDescriptorPtr);
#else
							using (MemoryMappedFile fileMap = MemoryMappedFile.OpenExisting(mapname, MemoryMappedFileRights.FullControl)) {
									if (!fileMap.SafeMemoryMappedFileHandle.IsInvalid) {
										SecurityIdentifier mapOwner = (SecurityIdentifier)fileMap.GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier));
#endif
									/* check to see if message sender is same user as this program's user */
									// TODO is this sufficient or should we do like Pageant does 
									// and retrieve sid from processes?
									WindowsIdentity user = WindowsIdentity.GetCurrent();
									SecurityIdentifier sid = user.User;

									if (sid == mapOwner) {
										AnswerMessage(fileMap);
										Marshal.WriteInt32(result, 1);
										return result; // success
									}
								}
#if DOT_NET_35
							} // if GetSecurityInfo
#else
						} // using fileMap
#endif // DOT_NET_35
						} catch (Exception ex) {
							Debug.Fail(ex.ToString());
						}
					}
				}
				return result; // failure
			} else {
				return DefWindowProcW(hWnd, msg, wParam, lParam);
			}
		}

#if DOT_NET_35
		private void AnswerMessage(IntPtr fileMap)
		{
			IntPtr map = MapViewOfFile(fileMap, FILE_MAP_WRITE, 0, 0, 0);
			byte[] fileCopy = new byte[AGENT_MAX_MSGLEN];
			Marshal.Copy(map, fileCopy, 0, AGENT_MAX_MSGLEN);
			Stream stream = new MemoryStream(fileCopy);
#else
		private void AnswerMessage(MemoryMappedFile fileMap)
		{
			using (MemoryMappedViewStream stream = fileMap.CreateViewStream()) {
#endif // DOT_NET_35
			Agent.AnswerMessage(stream, getSSH2PublicKeyListCallback,
        getSSH2PublicKeyCallback);
#if DOT_NET_35
			Marshal.Copy(fileCopy, 0, map, AGENT_MAX_MSGLEN);
			UnmapViewOfFile(fileMap);
#else
			} // using MemoryMappedViewStream stream
#endif
		}

		#endregion
	}

}
