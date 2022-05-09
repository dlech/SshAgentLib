//
// MsysSocket.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2014-2015 David Lechner
//
// Inspired by CCygSock and CCygSockChannel from PuttyAgent plugin for KeePass 1
// Copyright (C) 2014 Nikolaus Hammler <nikolaus@hammler.net>
//
// and also
// http://stackoverflow.com/questions/23086038/what-mechanism-is-used-by-msys-cygwin-to-emulate-unix-domain-sockets
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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace dlech.SshAgentLib
{
    public class MsysSocket : IDisposable
    {
        const string waitHandleNamePrefix = "cygwin.local_socket.secret";

        static int clientCount = 0;

        string path;
        Socket socket;
        Guid guid;
        string guidString;
        bool disposed;
        EventWaitHandle serverWaitHandle;
        List<Socket> clientSockets = new List<Socket>();
        object clientSocketsLock = new object();

        public delegate void ConnectionHandlerFunc(Stream stream, Process process);
        public ConnectionHandlerFunc ConnectionHandler { get; set; }

        /// <summary>
        /// Create new "unix domain" socket for use with MSYS
        /// </summary>
        /// <param name="path">The name of the file to use for the socket</param>
        public MsysSocket(string path)
        {
            this.path = path;
            guid = Guid.NewGuid();
            using (var stream = new FileStream(path, FileMode.CreateNew))
            using (var writer = new StreamWriter(stream))
            {
                try
                {
                    File.SetAttributes(path, FileAttributes.System);
                    var fileSecurity = File.GetAccessControl(path);
                    // This turns off ACL inheritance and removes all inherited rules
                    fileSecurity.SetAccessRuleProtection(true, false);
                    // We are left with no permissions at all, so we have to add them
                    // back for the current user
                    var userOnlyRule = new FileSystemAccessRule(
                        WindowsIdentity.GetCurrent().User,
                        FileSystemRights.FullControl,
                        AccessControlType.Allow
                    );
                    fileSecurity.SetAccessRule(userOnlyRule);
                    File.SetAccessControl(path, fileSecurity);
                    socket = new Socket(
                        AddressFamily.InterNetwork,
                        SocketType.Stream,
                        ProtocolType.Tcp
                    );
                    var endpoint = new IPEndPoint(IPAddress.Loopback, 0);
                    socket.Bind(endpoint);
                    socket.Listen(5);
                    var socketThread = new Thread(AcceptConnections);
                    socketThread.Name = "MsysSocket";
                    socketThread.Start();
                    writer.Write("!<socket >");
                    var actualPort = ((IPEndPoint)socket.LocalEndPoint).Port;
                    writer.Write(actualPort);
                    writer.Write(" ");
                    var guidBytes = guid.ToByteArray();
                    var builder = new StringBuilder();
                    for (var i = 0; i < 4; i++)
                    {
                        builder.Append(
                            string.Format("{0:X8}", BitConverter.ToUInt32(guidBytes, i * 4))
                        );
                        if (i < 3)
                            builder.Append("-");
                    }
                    guidString = builder.ToString();
                    writer.Write(guidString);
                    serverWaitHandle = new EventWaitHandle(
                        false,
                        EventResetMode.AutoReset,
                        string.Format(
                            "{0}.{1}.{2}",
                            waitHandleNamePrefix,
                            (UInt16)IPAddress.HostToNetworkOrder((Int16)actualPort),
                            guidString
                        )
                    );
                }
                catch (Exception)
                {
                    if (socket != null)
                        socket.Close();
                    File.Delete(path);
                    throw;
                }
            }
        }

        /// <summary>
        /// Tests a file to see if it looks like a Cygwin socket file
        /// </summary>
        /// <param name="path">The path to the file.</param>
        /// <returns><c>true</c> if the file contents look correct</returns>
        public static bool TestFile(string path)
        {
            var test = new Regex(@"!<socket >\d+ (?:[0-9A-Fa-f]{8}-?){4}");
            return test.Match(File.ReadAllText(path)).Success;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        void Dispose(bool disposing)
        {
            if (!disposed)
            {
                disposed = true;
                if (disposing)
                {
                    // Dispose managed resources
                    foreach (var clientSocket in clientSockets)
                    {
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
            while (true)
            {
                try
                {
                    var clientSocket = socket.Accept();
                    var clientThread = new Thread(
                        () =>
                        {
                            try
                            {
                                using (var stream = new NetworkStream(clientSocket))
                                {
                                    try
                                    {
                                        var clientPort = (
                                            (IPEndPoint)clientSocket.RemoteEndPoint
                                        ).Port;
                                        var clientWaitHandleName = string.Format(
                                            "{0}.{1}.{2}",
                                            waitHandleNamePrefix,
                                            (UInt16)IPAddress.HostToNetworkOrder((Int16)clientPort),
                                            guidString
                                        );
                                        var clientWaitHandle = EventWaitHandle.OpenExisting(
                                            clientWaitHandleName
                                        );
                                        if (
                                            !EventWaitHandle.SignalAndWait(
                                                serverWaitHandle,
                                                clientWaitHandle,
                                                10000,
                                                false
                                            )
                                        )
                                        {
                                            return;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Debug.Fail(ex.ToString());
                                    }
                                    Process proc = null;
                                    try
                                    {
                                        // remote and local are swapped because we are doing reverse lookup
                                        proc = WinInternals.GetProcessForTcpPort(
                                            (IPEndPoint)clientSocket.RemoteEndPoint,
                                            (IPEndPoint)clientSocket.LocalEndPoint
                                        );
                                    }
                                    catch (Exception ex)
                                    {
                                        Debug.Fail(ex.ToString());
                                    }
                                    if (ConnectionHandler != null)
                                    {
                                        ConnectionHandler(stream, proc);
                                    }
                                }
                            }
                            catch
                            {
                                // can throw if remote closes the connection at a bad time
                            }
                            finally
                            {
                                lock (clientSocketsLock)
                                {
                                    clientSockets.Remove(clientSocket);
                                }
                            }
                        }
                    );
                    lock (clientSocketsLock)
                    {
                        clientSockets.Add(clientSocket);
                    }
                    clientThread.Name = string.Format("MsysClient{0}", clientCount++);
                    clientThread.Start();
                }
                catch (Exception ex)
                {
                    Debug.Assert(disposed, ex.ToString());
                    break;
                }
            }
        }
    }
}
