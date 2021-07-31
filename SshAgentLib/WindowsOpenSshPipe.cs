//
// WindowsOpenSshPipe.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2017 David Lechner
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
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;

namespace dlech.SshAgentLib
{
  public class WindowsOpenSshPipe : IDisposable
  {
    private const string agentPipeId = "openssh-ssh-agent";
    private const int receiveBufferSize = 5 * 1024;

    private static uint threadId;

    private NamedPipeServerStream listeningServer;


    public delegate void ConnectionHandlerFunc(Stream stream, Process process);
    public ConnectionHandlerFunc ConnectionHandler { get; set; }

    public WindowsOpenSshPipe()
    {
      if (File.Exists($"//./pipe/{agentPipeId}")) {
        throw new PageantRunningException();
      }
      var thread = new Thread(listenerThread) {
        Name = "WindowsOpenSshPipe.Listener",
        IsBackground = true
      };
      thread.Start();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

    private void listenerThread()
    {
      try {
        while (true) {
          var server = new NamedPipeServerStream(agentPipeId, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.WriteThrough, receiveBufferSize, receiveBufferSize);
          listeningServer = server;
          server.WaitForConnection();
          listeningServer = null;
          var thread = new Thread(connectionThread) {
            Name = $"WindowsOpenSshPipe.Connection{threadId++}",
            IsBackground = true
          };
          thread.Start(server);
        }
      }
      catch (Exception) {
        // don't crash background thread
      }
    }

    private void connectionThread(object obj)
    {
      try {
        var server = obj as NamedPipeServerStream;

        if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var clientPid)) {
          throw new IOException("Failed to get client PID", Marshal.GetHRForLastWin32Error());
        }
        var proc = Process.GetProcessById((int)clientPid);

        ConnectionHandler(server, proc);
        server.Disconnect();
        server.Dispose();
      }
      catch (Exception) {
        // TODO: add event to notify when there is a problem
      }
    }

    public void Dispose()
    {
      Dispose(true);
      GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
      if (disposing) {
        if (listeningServer != null) {
          listeningServer.Dispose();
          listeningServer = null;
        }
      }
    }
  }
}
