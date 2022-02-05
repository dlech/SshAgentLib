//
// WindowsOpenSshClient.cs
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
using System.IO.Pipes;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Windows OpenSSH client
    /// </summary>
    public class WindowsOpenSshClient : AgentClient
    {
        const int BufferSize = 5 * 1024;
        const string agentPipeId = "openssh-ssh-agent";

        public override byte[] SendMessage(byte[] message)
        {
            using (var pipe = new NamedPipeClientStream(agentPipeId))
            {
                pipe.Connect(500);
                pipe.Write(message, 0, message.Length);
                pipe.Flush();
                var reply = new byte[BufferSize];
                pipe.Read(reply, 0, reply.Length);
                return reply;
            }
        }
    }
}
