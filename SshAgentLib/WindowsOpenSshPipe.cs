// SPDX-License-Identifier: MIT
// Copyright (c) 2017,2022 David Lechner <david@lechnology.com>

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

using ConnectionHandler = System.Action<System.IO.Stream, System.Diagnostics.Process>;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// A named pipe server for Windows OpenSSH.
    /// </summary>
    public sealed class WindowsOpenSshPipe : IDisposable
    {
        private const string agentPipeId = "openssh-ssh-agent";
        private const int bufferSize = 5 * 1024; // 5 KiB

        private readonly CancellationTokenSource cancelSource;
        private readonly Task listenerTask;

        /// <summary>
        /// Creates a new Windows OpenSSH Agent pipe.
        /// </summary>
        /// <param name="connectionHandler">
        /// A callback for handling client connections.
        /// </param>
        /// <exception cref="PageantRunningException">
        /// Thrown if the pipe file path is already in use.
        /// </exception>
        public WindowsOpenSshPipe(ConnectionHandler connectionHandler)
        {
            if (File.Exists($"//./pipe/{agentPipeId}"))
            {
                throw new PageantRunningException();
            }

            cancelSource = new CancellationTokenSource();
            listenerTask = RunListenerAsync(connectionHandler, cancelSource.Token);
            Debug.WriteLine("Started new Windows OpenSSH Pipe");
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(
            IntPtr Pipe,
            out uint ClientProcessId
        );

        private static async Task RunListenerAsync(
            ConnectionHandler connectionHandler,
            CancellationToken cancellationToken
        )
        {
#if __MonoCS__
            // implementation causes compiler to crash
            await Task.Run(
                () =>
                {
                    throw new NotImplementedException();
                }
            );
#else
            while (!cancellationToken.IsCancellationRequested)
            {
                var security = new PipeSecurity();

                // Limit access to the current user. This also has the effect
                // of allowing non-elevated processes to access the agent when
                // it is running as an elevated process.
                security.AddAccessRule(
                    new PipeAccessRule(
                        WindowsIdentity.GetCurrent().User,
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow
                    )
                );

                using (
                    var server = new NamedPipeServerStream(
                        agentPipeId,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.WriteThrough | PipeOptions.Asynchronous,
                        bufferSize,
                        bufferSize,
                        security
                    )
                )
                {
                    await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                    Debug.WriteLine("Received Windows OpenSSH Pipe client connection");

                    if (
                        !GetNamedPipeClientProcessId(
                            server.SafePipeHandle.DangerousGetHandle(),
                            out var clientPid
                        )
                    )
                    {
                        throw new IOException(
                            "Failed to get client PID",
                            Marshal.GetHRForLastWin32Error()
                        );
                    }

                    try
                    {
                        var proc = Process.GetProcessById((int)clientPid);

                        using (cancellationToken.Register(() => server.Disconnect()))
                        {
                            await Task.Run(() => connectionHandler(server, proc), cancellationToken)
                                .ConfigureAwait(false);
                        }
                    }
                    catch (ArgumentException)
                    {
                        // The SSH client process is gone! Nothing we can do ...
                        Debug.WriteLine($"OpenSSH pipe client already exited (PID: {clientPid})");
                    }
                }
            }
#endif
        }

        public void Dispose()
        {
            // allow multiple calls to dispose
            if (listenerTask.IsCompleted)
            {
                return;
            }

            cancelSource.Cancel();

            try
            {
                listenerTask.Wait();
            }
            catch (AggregateException)
            {
                // expected since we just canceled the task
            }

            Debug.WriteLine("Stopped Windows OpenSSH Pipe");
        }
    }
}
