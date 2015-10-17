//
// UnixAgentTest.cs
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
using System.Net.Sockets;
using System.Reflection;
using dlech.SshAgentLib;
using Mono.Unix;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{
  [TestFixture]
  [Platform(Exclude="Win")]
  public class UnixAgentTest
  {
    /// <summary>
    /// Tests that the socket file is deleted on Dispose.
    /// </summary>
    [Test]
    public void TestUnixAgentDispose()
    {
      const string socketFileName = "test1.socket";

      if (File.Exists (socketFileName)) {
        File.Delete(socketFileName);
      }

      using (var agent = new UnixAgent(socketFileName)) {
        Assert.That(File.Exists(socketFileName), Is.True,
          "Failed to create socket file");
      }
      // check that temporary directory was cleaned up after dispose
      Assert.That(File.Exists(socketFileName), Is.False,
        "Socket file was not deleted");
    }

    [Test]
    public void TestUnixAgentBadMessage()
    {
      const string socketFileName = "test2.socket";

      if (File.Exists (socketFileName)) {
        File.Delete(socketFileName);
      }

      using (var agent = new UnixAgent(socketFileName))
      using (var client = new Mono.Unix.UnixClient(socketFileName))
      using (var stream = client.GetStream ()) {
        var message = new byte[] { 0, 0, 0, 0 };
        stream.Write(message, 0, message.Length); // send garbage
        stream.Flush();
        var reply = new byte[5];
        stream.Read(reply, 0, reply.Length);
        var expected = new byte [] {
          0, 0, 0, 1,
          (byte)Agent.Message.SSH_AGENT_FAILURE,
        };
        Assert.That(reply, Is.EqualTo(expected));
      }
    }

    [Test]
    public void TestUnixAgentGoodMessage()
    {
      const string socketFileName = "test3.socket";

      if (File.Exists(socketFileName)) {
        File.Delete(socketFileName);
      }

      using (var agent = new UnixAgent(socketFileName))
      using (var client = new Mono.Unix.UnixClient(socketFileName))
      using (var stream = client.GetStream()) {
        var message = new byte[] {
          0, 0, 0, 1,
          (byte)Agent.Message.SSH1_AGENTC_REQUEST_RSA_IDENTITIES,
        };
        stream.Write(message, 0, message.Length); // send message
        stream.Flush();
        var reply = new byte[9];
        stream.Read(reply, 0, reply.Length);
        var expected = new byte[] {
          0, 0, 0, 5,
          (byte)Agent.Message.SSH1_AGENT_RSA_IDENTITIES_ANSWER,
          0, 0, 0, 0,
        };
        Assert.That(reply, Is.EqualTo(expected));
      }
    }
  }
}
