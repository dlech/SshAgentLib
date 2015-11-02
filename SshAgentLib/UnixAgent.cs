//
// UnixAgent.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013,2015 David Lechner
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
using System.Net.Sockets;
using System.Threading;
using AsyncSocketSample;
using Mono.Unix;
using Mono.Unix.Native;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// ssh-agent for linux
  /// </summary>
  /// <remarks>
  /// Code based on ssh-agent.c from OpenBSD/OpenSSH and
  /// http://msdn.microsoft.com/en-us/library/system.net.sockets.socketasynceventargs.aspx
  /// </remarks>
  public class UnixAgent : Agent
  {
    /* Listen backlog for sshd, ssh-agent and forwarding sockets */
    const int sshListenBacklog = 128;
    const int maxNumConnections = 10;
    const int receiveBufferSize = 4096;

    UnixListener listener;
    Thread connectionThread;
    bool isDisposed;

    public void StartUnixSocket(string socketPath)
    {
      if (socketPath == null) {
        throw new ArgumentNullException("socketPath");
      }
      try {
        socketPath = Path.GetFullPath(socketPath);
        if (File.Exists(socketPath)) {
          var info = UnixFileSystemInfo.GetFileSystemEntry(socketPath);
          if (info.IsSocket) {
            // if the file is a socket, it probably came from us, so overwrite it.
            File.Delete(socketPath);
          } else {
            // don't want to overwrite anything that is not a socket file though.
            var message = string.Format("The file '{0}' already exists.", socketPath);
            throw new Exception(message);
          }
        }

        // set file permission to user only.
        var prevUmask = Syscall.umask(
          FilePermissions.S_IXUSR |
          FilePermissions.S_IRWXG |
          FilePermissions.S_IRWXO);
        // file is created in UnixListener()
        try {
          listener = new UnixListener(socketPath);
        } finally {
          Syscall.umask(prevUmask);
        }
        listener.Start ();
        connectionThread = new Thread(AcceptConnections) { Name = "UnixAgent" };
        connectionThread.Start ();

      } catch (Exception ex) {
        var message = string.Format("Failed to start Unix Agent: {0}", ex.Message);
        throw new Exception(message, ex);
      }
    }

    public void StopUnixSocket()
    {
      // work around mono bug. listener.Dispose() should delete file, but it
      // fails because there are null chars appended to the end of the filename
      // for some reason.
      // See: https://bugzilla.xamarin.com/show_bug.cgi?id=35004
      var socketPath = ((UnixEndPoint)listener.LocalEndpoint).Filename;
      var nullTerminatorIndex = socketPath.IndexOf('\0');
      listener.Dispose();
      if (nullTerminatorIndex > 0) {
        try {
          socketPath = socketPath.Remove(nullTerminatorIndex);
          File.Delete(socketPath);
        } catch {
          // well, we tried
        }
      }
    }

    void AcceptConnections()
    {
      while (true) {
        try {
          using (var client = listener.AcceptUnixClient())
          using (var stream = client.GetStream()) {
            try {
              while (true) {
                AnswerMessage(stream);
              }
            } catch (Exception) {
              // happens when client closes connection
            }
          }
        } catch (Exception) {
          break;
        }
      }
    }

    public override void Dispose()
    {
      Dispose(true);
      GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
      if (!isDisposed) {
        if (disposing) {
          StopUnixSocket();
        }
      }
      isDisposed = true;
    }

    ~UnixAgent()
    {
      Dispose(false);
    }
  }
}
