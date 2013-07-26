//
// UnixClient.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013 David Lechner
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
using System.IO;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// ssh-agent for linux
  /// </summary>
  /// <remarks>
  /// Code based on ssh-agent.c from OpenBSD/OpenSSH and
  /// http://msdn.microsoft.com/en-us/library/system.net.sockets.socketasynceventargs.aspx
  /// </remarks>
  public class UnixClient : AgentClient
  {
    /* constants */

    /* Name of the environment variable containing the pathname of the
     * authentication socket. */
    public static string SSH_AUTHSOCKET_ENV_NAME = "SSH_AUTH_SOCK";
    public static int cBufferSize = 4096;


    /* constructor */

    public UnixClient()
    {

    }

    public override byte[] SendMessage(byte[] aMessage)
    {
      var socketPath =
        Environment.GetEnvironmentVariable(SSH_AUTHSOCKET_ENV_NAME);
      if (!File.Exists(socketPath)) {
        throw new AgentNotRunningException();
      }
      using (var client = new Mono.Unix.UnixClient (socketPath)) {
        using (var stream = client.GetStream()) {
          stream.Write(aMessage, 0, aMessage.Length);
          byte[] reply = new byte[cBufferSize];
          stream.Read(reply, 0, reply.Length);
          return reply;
        }
      }
    }
  }
}
