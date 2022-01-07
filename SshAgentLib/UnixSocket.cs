//
// UnixSocket.cs
//
// Allows WSL1 connections via AF_UNIX sockets on Windows 10 and above.
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

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace dlech.SshAgentLib
{
  public class UnixSocket : IDisposable
  {
    const string waitHandleNamePrefix = "unix.local_socket.secret";

    static int clientCount = 0;

    string path;
    Socket socket;
    SocketAddress sockaddr;
    Guid guid;
    bool disposed;
    List<Socket> clientSockets = new List<Socket>();
    object clientSocketsLock = new object();

    public delegate void ConnectionHandlerFunc(Stream stream, Process process);
    public ConnectionHandlerFunc ConnectionHandler { get; set; }

    /// <summary>
    /// Create new "unix domain" socket for use with Linux
    /// </summary>
    /// <param name="path">The name of the file to use for the socket</param>
    public UnixSocket(string path)
    {
      this.path = path;
      guid = Guid.NewGuid();
      {
        try {
          socket = new Socket(AddressFamily.Unix, SocketType.Stream,
            ProtocolType.Unspecified);
          var endpoint = new UnixEndPoint(path);
          sockaddr = endpoint.Serialize();
          socket.Bind(endpoint);
          var fileSecurity = File.GetAccessControl(path);
          // This turns off ACL inheritance and removes all inherited rules
          fileSecurity.SetAccessRuleProtection(true, false);
          // We are left with no permissions at all, so we have to add them
          // back for the current user
          var userOnlyRule = new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User,
            FileSystemRights.FullControl,
            AccessControlType.Allow);
          fileSecurity.SetAccessRule(userOnlyRule);
          File.SetAccessControl(path, fileSecurity);
          socket.Listen(5);
          var socketThread = new Thread(AcceptConnections);
          socketThread.Name = "UnixSocket";
          socketThread.Start();
        } catch (Exception) {
          if (socket != null)
            socket.Close();
          File.Delete(path);
          throw;
        }
      }
    }

    /// <summary>
    /// Tests a file to see if it looks like a Unix socket file
    /// </summary>
    /// <param name="path">The path to the file.</param>
    /// <returns><c>true</c> if the file contents look correct</returns>
    public static bool TestFile(string path)
    {
      var info = new FileInfo(path);
      return info.Length == 0;
    }

    public void Dispose()
    {
      Dispose(true);
      GC.SuppressFinalize(this);
    }

    void Dispose(bool disposing)
    {
      if (!disposed) {
        disposed = true;
        if (disposing) {
          // Dispose managed resources
          foreach (var clientSocket in clientSockets) {
            clientSocket.Dispose();
          }
          socket.Dispose();
          File.Delete(path);
        }
        // Dispose unmanaged resources
      }
    }

    void AcceptConnections()
    {
      var buffer = new byte[16];
      while (true) {
        try {
          BindingFlags
            sbinding = BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public,
            ibinding = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
          var args = new object[]
          {
            typeof(Socket).GetField("m_Handle", ibinding).GetValue(socket),
            (byte[])typeof(SocketAddress).GetField("m_Buffer", ibinding).GetValue(sockaddr),
            sockaddr.Size
          };
          var acceptedHandle = (SafeHandleMinusOneIsInvalid)typeof(Socket).Assembly.GetType("System.Net.SafeCloseSocket").GetMethod("Accept", sbinding).Invoke(null, args);
          // Accept() returns the socket address for the accepted connection, along with its size.
          // We want the SocketAddress object to contain that address when creating the endpoint.
          // We use reflection to access the field since there is no public setter.
          // This is safe because accept() returns the actual number of bytes written to the buffer, so the output cannot overflow the buffer.
          typeof(SocketAddress).GetField("m_Size", ibinding).SetValue(sockaddr, (int)args[2]);
          var endpoint = new UnixEndPoint(null).Create(sockaddr);
          var clientSocket = acceptedHandle.IsInvalid ? null : (Socket)typeof(Socket).GetMethod("CreateAcceptSocket", ibinding).Invoke(socket, new object[] { acceptedHandle, endpoint, false });
          if (clientSocket == null) { Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); }
          var clientThread = new Thread(() => {
            try {
              using (var stream = new NetworkStream(clientSocket)) {
                Process proc = null;
                if (ConnectionHandler != null) {
                  ConnectionHandler(stream, proc);
                }
              }
            } catch {
              // can throw if remote closes the connection at a bad time
            } finally {
              lock (clientSocketsLock) {
                clientSockets.Remove(clientSocket);
              }
            }
          });
          lock (clientSocketsLock) {
            clientSockets.Add(clientSocket);
          }
          clientThread.Name = string.Format("UnixClient{0}", clientCount++);
          clientThread.Start();
        } catch (Exception ex) {
          Debug.Assert(disposed, ex.ToString());
          break;
        }
      }
    }
  }

  [Serializable]
  public class UnixEndPoint : EndPoint
  {
    public string Filename { get; private set; }

    public UnixEndPoint(string path) : base()
    {
      this.Filename = path;
    }

    public override AddressFamily AddressFamily { get { return AddressFamily.Unix; } }

    public override EndPoint Create(SocketAddress socketAddress)
    {
      int size = socketAddress.Size - 2;
      var bytes = new byte[size];
      for (int i = 0; i < bytes.Length; i++)
      {
        bytes[i] = socketAddress[i + 2];
        if (i > 0 && bytes[i] == 0)
        {
          size = i;
          break;
        }
      }
      return new UnixEndPoint(Encoding.UTF8.GetString(bytes, 0, size));
    }
    public override SocketAddress Serialize()
    {
      var bytes = Encoding.UTF8.GetBytes(this.Filename);
      var maxLen = 108;
      if (bytes.Length > maxLen) {
        throw new PathTooLongException(string.Format("Path ({0} bytes) was too long for UNIX-domain socket (max {1} bytes)", bytes.Length, maxLen));
      }
      var addr = new SocketAddress(AddressFamily.Unix, sizeof(short) + maxLen);
      for (int i = 0; i < bytes.Length && i < maxLen; i++)
      {
        addr[2 + i] = bytes[i];
      }
      if (bytes.Length < maxLen) { 
        addr[sizeof(short) + bytes.Length] = 0;
      }
      return addr;
    }
  }
}
