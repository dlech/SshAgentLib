using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
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
        Environment.ExpandEnvironmentVariables(SSH_AUTHSOCKET_ENV_NAME);
      if (!File.Exists(socketPath)) {
        // TODO should be AgentNotRunningException
        throw new PageantNotRunningException();
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

