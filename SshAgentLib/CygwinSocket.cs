﻿//
// CygwinSocket.cs
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
    public class CygwinSocket : IDisposable
    {
        const string waitHandleNamePrefix = "cygwin.local_socket.secret";

        static int clientCount = 0;

        string path;
        Socket socket;
        Guid guid;
        bool disposed;
        List<Socket> clientSockets = new List<Socket>();
        object clientSocketsLock = new object();

        public delegate void ConnectionHandlerFunc(Stream stream, Process process);
        public ConnectionHandlerFunc ConnectionHandler { get; set; }

        /// <summary>
        /// Create new "unix domain" socket for use with Cygwin
        /// </summary>
        /// <param name="path">The name of the file to use for the socket</param>
        public CygwinSocket(string path)
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
                    socketThread.Name = "CygwinSocket";
                    socketThread.Start();
                    writer.Write("!<socket >");
                    var actualPort = ((IPEndPoint)socket.LocalEndPoint).Port;
                    writer.Write(actualPort);
                    writer.Write(" s ");
                    var guidBytes = guid.ToByteArray();
                    for (var i = 0; i < 4; i++)
                    {
                        writer.Write(
                            string.Format("{0:X8}", BitConverter.ToUInt32(guidBytes, i * 4))
                        );
                        if (i < 3)
                            writer.Write("-");
                    }
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
            var test = new Regex(@"!<socket >\d+ s (?:[0-9A-Fa-f]{8}-?){4}");
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
            var buffer = new byte[16];
            while (true)
            {
                try
                {
                    var clientSocket = socket.Accept();
                    var clientThread = new Thread(() =>
                    {
                        try
                        {
                            using (var stream = new NetworkStream(clientSocket))
                            {
                                stream.Read(buffer, 0, 16);
                                var incomingGuid = new Guid(buffer);
                                if (incomingGuid != guid)
                                {
                                    return;
                                }
                                stream.Write(buffer, 0, 16);
                                stream.Flush();
                                stream.Read(buffer, 0, 12);
                                var pid = BitConverter.ToInt32(buffer, 0);
                                // var gid = BitConverter.ToInt32(buffer, 4);
                                // var uid = BitConverter.ToInt32(buffer, 8);
                                // FIXME: This should be a cygwin pid, not a windows pid
                                // seems to work fine though
                                pid = Process.GetCurrentProcess().Id;
                                Array.Copy(BitConverter.GetBytes(pid), buffer, 4);
                                stream.Write(buffer, 0, 12);
                                stream.Flush();
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
                    });
                    lock (clientSocketsLock)
                    {
                        clientSockets.Add(clientSocket);
                    }
                    clientThread.Name = string.Format("CygwinClient{0}", clientCount++);
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
