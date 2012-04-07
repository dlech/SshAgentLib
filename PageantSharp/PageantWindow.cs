using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Security.Principal;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Text;

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
	public class PageantWindow : IDisposable
	{
		#region /* constants */

		/* From WINAPI */

		private const int ERROR_CLASS_ALREADY_EXISTS =       1410;
		private const int WM_COPYDATA =                      0x004A;


		/* From PuTTY source code */

		private const string className = "Pageant";

		private const int AGENT_COPYDATA_ID = unchecked((int)0x804e50ba);

		private const int SSH_AGENT_BAD_REQUEST =								 -1; // not from PuTTY source

		/*
		 * SSH-1 agent messages.
		 */
		private const int SSH1_AGENTC_REQUEST_RSA_IDENTITIES =    1;
		private const int SSH1_AGENT_RSA_IDENTITIES_ANSWER =      2;
		private const int SSH1_AGENTC_RSA_CHALLENGE =             3;
		private const int SSH1_AGENT_RSA_RESPONSE =               4;
		private const int SSH1_AGENTC_ADD_RSA_IDENTITY =          7;
		private const int SSH1_AGENTC_REMOVE_RSA_IDENTITY =       8;
		private const int SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9; /* openssh private? */

		/*
		 * Messages common to SSH-1 and OpenSSH's SSH-2.
		 */
		private const int SSH_AGENT_FAILURE =                     5;
		private const int SSH_AGENT_SUCCESS =                     6;

		/*
		 * OpenSSH's SSH-2 agent messages.
		 */
		private const int SSH2_AGENTC_REQUEST_IDENTITIES =        11;
		private const int SSH2_AGENT_IDENTITIES_ANSWER =          12;
		private const int SSH2_AGENTC_SIGN_REQUEST =              13;
		private const int SSH2_AGENT_SIGN_RESPONSE =              14;
		private const int SSH2_AGENTC_ADD_IDENTITY =              17;
		private const int SSH2_AGENTC_REMOVE_IDENTITY =           18;
		private const int SSH2_AGENTC_REMOVE_ALL_IDENTITIES =     19;

		#endregion


		#region /* global variables */

		private bool disposed;
		private IntPtr hwnd;
		private WndProc customWndProc;

		GetSSH2KeysCallback getSSH2KeysCallback;

		#endregion


		#region /* delegates */

		private delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

		public delegate IEnumerable<PpkKey> GetSSH2KeysCallback();

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



		#endregion


		#region /* constructors */

		/// <summary>
		/// Creates a new instance of PageantWindow. This window is not meant to be used for UI.
		/// 
		/// </summary>
		/// <exception cref="PageantException">Thrown when another instance of Pageant is running.</exception>
		public PageantWindow(GetSSH2KeysCallback getRSACollectionCallback)
		{
			if (CheckAlreadyRunning()) {
				throw new PageantException();
			}

			/* assign callbacks */
			this.getSSH2KeysCallback = getRSACollectionCallback;

			// create reference to delegate so that garbage collector does not eat it.
			this.customWndProc = new WndProc(CustomWndProc);

			// Create WNDCLASS
			WNDCLASS wind_class = new WNDCLASS();
			wind_class.lpszClassName = PageantWindow.className;
			wind_class.lpfnWndProc = this.customWndProc;

			UInt16 class_atom = RegisterClassW(ref wind_class);

			int last_error = Marshal.GetLastWin32Error();

			// TODO do we really need to worry about an error when regisering class?
			if (class_atom == 0 && last_error != PageantWindow.ERROR_CLASS_ALREADY_EXISTS) {
				throw new System.Exception("Could not register window class");
			}

			// Create window
			this.hwnd = CreateWindowExW(
					0, // dwExStyle
					PageantWindow.className, // lpClassName
					PageantWindow.className, // lpWindowName
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
			IntPtr hwnd = FindWindow(PageantWindow.className, PageantWindow.className);
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
			if (msg == WM_COPYDATA) {
				IntPtr result = Marshal.AllocHGlobal(sizeof(int));
				Marshal.WriteInt32(result, 0);

				//Message message = Message.Create(hWnd, (int)msg, wParam, lParam);
				//COPYDATASTRUCT copyData = (COPYDATASTRUCT)message.GetLParam(typeof(COPYDATASTRUCT));
				COPYDATASTRUCT copyData = (COPYDATASTRUCT)Marshal.PtrToStructure(lParam, typeof(COPYDATASTRUCT));
				if (copyData.dwData.ToInt32() != AGENT_COPYDATA_ID) {
					return result; // not our message, mate   ;)
				}
				string mapname = Marshal.PtrToStringAnsi(copyData.lpData);
				if (mapname.Length != copyData.cbData - 1) {
					return result; // data was not ascii string
				}
				try {
					MemoryMappedFile fileMap = MemoryMappedFile.OpenExisting(mapname, MemoryMappedFileRights.FullControl);
					if (!fileMap.SafeMemoryMappedFileHandle.IsInvalid) {

						// TODO is this sufficent or should we do like Pageant does 
						// and retreive sid from processes?
						WindowsIdentity user = WindowsIdentity.GetCurrent();
						SecurityIdentifier sid = user.User;
						SecurityIdentifier mapOwner = (SecurityIdentifier)fileMap.GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier));
						if (sid == mapOwner) {
							AnswerMessage(fileMap);
							Marshal.WriteInt32(result, 1);
							return result;
						}
					}
					fileMap.Dispose();
				} catch (Exception) {
					return result;
				}
			}
			// TODO finish implement window messaging
			return DefWindowProcW(hWnd, msg, wParam, lParam);
		}

		private void AnswerMessage(MemoryMappedFile fileMap)
		{

			using (MemoryMappedViewStream stream = fileMap.CreateViewStream()) {

				byte[] buffer = new byte[4];
				stream.Read(buffer, 0, 4);
				int msgDataLength = PSUtil.BytesToInt(buffer, 0);
				int type;

				if (msgDataLength > 0) {
					stream.Position = 4;
					type = stream.ReadByte();
				} else {
					type = SSH_AGENT_BAD_REQUEST;
				}
				switch (type) {
					case SSH1_AGENTC_REQUEST_RSA_IDENTITIES:
						/*
						 * Reply with SSH1_AGENT_RSA_IDENTITIES_ANSWER.
						 */


						break;
					case SSH2_AGENTC_REQUEST_IDENTITIES:
						/*
						 * Reply with SSH2_AGENT_IDENTITIES_ANSWER.
						 */
						if (this.getSSH2KeysCallback != null) {
							PpkKeyBlobBuilder builder = new PpkKeyBlobBuilder();
							try {
								int keyCount = 0;
								foreach (PpkKey key in this.getSSH2KeysCallback()) {
									keyCount++;
									builder.AddBlob(key.GetSSH2PublicKeyBlob());
									builder.AddString(key.Comment);
								}

								if (9 + builder.Length <= stream.Length) {
									stream.Position = 0;
									stream.Write(PSUtil.IntToBytes(5 + builder.Length), 0, 4);
									stream.WriteByte(SSH2_AGENT_IDENTITIES_ANSWER);
									stream.Write(PSUtil.IntToBytes(keyCount), 0, 4);
									stream.Write(builder.getBlob(), 0, builder.Length);
									break; // succeeded
								}
							} catch (Exception ex) {
								Debug.Fail(ex.ToString());
							} finally {
								builder.Clear();
							}
						}
						goto default; // failed
					case SSH1_AGENTC_RSA_CHALLENGE:
						/*
						 * Reply with either SSH1_AGENT_RSA_RESPONSE or
						 * SSH_AGENT_FAILURE, depending on whether we have that key
						 * or not.
						 */

						// TODO implement SSH1_AGENTC_RSA_CHALLENGE

						goto default; // failed
					case SSH2_AGENTC_SIGN_REQUEST:
						/*
						 * Reply with either SSH2_AGENT_SIGN_RESPONSE or
						 * SSH_AGENT_FAILURE, depending on whether we have that key
						 * or not.
						 */
						try {

							/* read rest of message */

							if (msgDataLength >= stream.Position + 4) {
								stream.Read(buffer, 0, 4);
								int keyBlobLength = PSUtil.BytesToInt(buffer, 0);
								if (msgDataLength >= stream.Position + keyBlobLength) {
									byte[] keyBlob = new byte[keyBlobLength];
									stream.Read(keyBlob, 0, keyBlobLength);
									if (msgDataLength >= stream.Position + 4) {
										stream.Read(buffer, 0, 4);
										int reqDataLength = PSUtil.BytesToInt(buffer, 0);
										if (msgDataLength >= stream.Position + reqDataLength) {
											byte[] reqData = new byte[reqDataLength];
											stream.Read(reqData, 0, reqDataLength);

											/* get matching key from callback */

											// TODO find matching key
											List<PpkKey> keyList = new List<PpkKey>(this.getSSH2KeysCallback());
											PpkKey key = keyList[0];
											if (key != null) {

												/* create signature */

												AsymmetricSignatureFormatter signer = null;
												if (typeof(RSA).IsInstanceOfType(key.Algorithm)) {
													signer = new RSAPKCS1SignatureFormatter();
												}
												if (typeof(DSA).IsInstanceOfType(key.Algorithm)) {
													signer = new DSASignatureFormatter();
												}
												if (signer != null) {
													SHA1 sha = SHA1.Create();
													sha.ComputeHash(reqData);
													signer.SetKey(key.Algorithm);
													byte[] signature = signer.CreateSignature(sha);
													sha.Clear();

													PpkKeyBlobBuilder sigBlobBuilder = new PpkKeyBlobBuilder();
													sigBlobBuilder.AddString(PpkFile.PublicKeyAlgorithms.ssh_rsa);
													sigBlobBuilder.AddBlob(signature);
													signature = sigBlobBuilder.getBlob();
													sigBlobBuilder.Clear();

													/* write response to filemap */

													stream.Position = 0;
													stream.Write(PSUtil.IntToBytes(5 + signature.Length), 0, 4);
													stream.WriteByte(SSH2_AGENT_SIGN_RESPONSE);
													stream.Write(PSUtil.IntToBytes(signature.Length), 0, 4);
													stream.Write(signature, 0, signature.Length);
													break; // succeeded
												}
											}
										}
									}
								}

							}
						} catch (Exception ex) {
							Debug.Fail(ex.ToString());
						}
						goto default; // failure
					case SSH1_AGENTC_ADD_RSA_IDENTITY:
						/*
						 * Add to the list and return SSH_AGENT_SUCCESS, or
						 * SSH_AGENT_FAILURE if the key was malformed.
						 */

						// TODO implement SSH1_AGENTC_ADD_RSA_IDENTITY

						goto default; // failed
					case SSH2_AGENTC_ADD_IDENTITY:
						/*
						 * Add to the list and return SSH_AGENT_SUCCESS, or
						 * SSH_AGENT_FAILURE if the key was malformed.
						 */

						// TODO implement SSH2_AGENTC_ADD_IDENTITY

						goto default; // failed
					case SSH1_AGENTC_REMOVE_RSA_IDENTITY:
						/*
						 * Remove from the list and return SSH_AGENT_SUCCESS, or
						 * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
						 * start with.
						 */

						// TODO implement SSH1_AGENTC_REMOVE_RSA_IDENTITY

						goto default; // failed
					case SSH2_AGENTC_REMOVE_IDENTITY:
						/*
						 * Remove from the list and return SSH_AGENT_SUCCESS, or
						 * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
						 * start with.
						 */

						// TODO implement SSH2_AGENTC_REMOVE_IDENTITY

						goto default; // failed
					case SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
						/*
						 * Remove all SSH-1 keys. Always returns success.
						 */

						// TODO implement SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES

						goto default; // failed
					case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
						/*
						 * Remove all SSH-2 keys. Always returns success.
						 */

						// TODO implement SSH2_AGENTC_REMOVE_ALL_IDENTITIES

						goto default; // failed

					case SSH_AGENT_BAD_REQUEST:
					default:
						stream.Position = 0;
						stream.Write(PSUtil.IntToBytes(1), 0, 4);
						stream.WriteByte(SSH_AGENT_FAILURE);
						break;
				}
			}
		}

		#endregion
	}

}
