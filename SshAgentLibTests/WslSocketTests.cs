// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System.IO;
using System.Net.Sockets;
using NUnit.Framework;
using dlech.SshAgentLib;
using System.Threading;

namespace dlech.SshAgentLibTests
{
    [TestFixture, NonParallelizable, Platform("Win")]
    public sealed class WslSocketTests
    {
        private const string testPath = "test-wsl-socket";

        [SetUp]
        public void Setup()
        {
            try
            {
                // Delete the socket file in case a bad test left it behind.
                File.Delete(testPath);
            }
            catch
            {
                // expected most of the time
            }
        }

        [Test, NonParallelizable]
        public void TestMultipleInstancesThrowsException()
        {
            using (new WslSocket(testPath, (s, p) => { }))
            {
                Assert.That(() => new WslSocket(testPath, (s2, p2) => { }),
                    Throws.TypeOf<PageantRunningException>());
            }
        }

        [Test, NonParallelizable]
        public void TestThatServerStopsListeningWhenDisposed()
        {
            using (new WslSocket(testPath, (s, p) => { }))
            {
                Assert.That(File.Exists(testPath),
                    "Creating pipe should create socket file");
            }
            Assert.That(!File.Exists(testPath),
                "Disposing pipe should remove file.");
        }

        [Test, NonParallelizable]
        public void TestThatSequentialConnectionsWork()
        {
            using (new WslSocket(testPath, (s, p) => { }))
            {
                var endpoint = new UnixDomainSocketEndPoint(testPath);

                using (var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
                {
                    client.Connect(endpoint);
                }

                using (var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
                {
                    client.Connect(endpoint);
                }
            }
        }

        [Test, NonParallelizable]
        public void TestThatDisposingWhileClientIsConnectedWorks()
        {
            var callbackEvent = new AutoResetEvent(false);

            using (var socket = new WslSocket(testPath, (s, p) =>
            {
                s.ReadByte();
                callbackEvent.Set();
                s.ReadByte();
                callbackEvent.Set();
            }))
            {
                var endpoint = new UnixDomainSocketEndPoint(testPath);

                using (var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
                {
                    client.Connect(endpoint);
                    client.Send(new byte[1]);
                    // have to wait for callback, otherwise we might dispose server
                    // before client connection is finished
                    callbackEvent.WaitOne(1000);
                    socket.Dispose();
                    Assert.That(() => client.Send(new byte[1]), Throws.TypeOf<SocketException>());
                }
            }
        }
    }
}
