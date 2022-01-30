// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2022 David Lechner <david@lechnology.com>

// Allows WSL connections via AF_UNIX sockets on Windows 10 and above.

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace dlech.SshAgentLib
{
    public class WslSocket : IDisposable
    {
        // https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
        private const int WSAEADDRINUSE = 10048;

        private readonly CancellationTokenSource cancelSource;
        private readonly Task socketTask;

        public delegate void ConnectionHandlerFunc(Stream stream, Process process);

        /// <summary>
        /// Create new "unix domain" socket for use with WSL.
        /// </summary>
        /// <param name="path">
        /// The name of the file to use for the socket.
        /// </param>
        /// <param name="connectionHandler">
        /// The callback that will be used to service client connetions.
        /// </param>
        public WslSocket(string path, ConnectionHandlerFunc connectionHandler)
        {
            var socket = new Socket(
                AddressFamily.Unix,
                SocketType.Stream,
                ProtocolType.Unspecified
            );

            try
            {
                var endpoint = new UnixDomainSocketEndPoint(path);
                try
                {
                    socket.Bind(endpoint);
                }
                catch (SocketException ex) when (ex.ErrorCode == WSAEADDRINUSE)
                {
                    throw new PageantRunningException();
                }

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

                socket.Listen(5);

                cancelSource = new CancellationTokenSource();
                socketTask = AcceptConnectionsAsync(socket, connectionHandler, cancelSource.Token);

                Debug.WriteLine("Started WSL socket");
            }
            catch (Exception)
            {
                socket.Dispose();
                try
                {
                    File.Delete(path);
                }
                catch { }
                throw;
            }
        }

        private static async Task AcceptConnectionsAsync(
            Socket socket,
            ConnectionHandlerFunc connectionHandler,
            CancellationToken cancellationToken
        )
        {
            cancellationToken.Register(
                () =>
                {
                    // have to get endpoint before Dispose() to avoid exception.
                    var endpoint = socket.LocalEndPoint as UnixDomainSocketEndPoint;
                    socket.Dispose();

                    // In .NET core, the Socket.Dispose() will take care of this, but
                    // for now...
                    try
                    {
                        File.Delete(endpoint.CreateBoundEndPoint().BoundFileName);
                    }
                    catch
                    {
                        // we tried
                    }
                }
            );

            while (!cancellationToken.IsCancellationRequested)
            {
                using (var clientSocket = await socket.AcceptAsync().ConfigureAwait(false))
                using (cancellationToken.Register(() => clientSocket.Close()))
                {
                    Debug.WriteLine("Accepted WSL socket client connection");

                    await Task.Run(
                            () =>
                            {
                                using (var stream = new NetworkStream(clientSocket))
                                {
                                    var proc = default(Process);
                                    connectionHandler(stream, proc);
                                }
                            }
                        )
                        .ConfigureAwait(false);
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
            cancelSource.Cancel();

            if (!socketTask.IsCompleted)
            {
                // allow Dispose to be called multiple times.
                return;
            }

            try
            {
                socketTask.Wait();
            }
            catch (AggregateException)
            {
                // happens because we canceled the task
            }

            Debug.WriteLine("Stopped WSL socket");
        }
    }
}
