// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System.IO;
using System.IO.Pipes;
using System.Threading;
using dlech.SshAgentLib;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{
    [TestFixture, NonParallelizable, Platform("Win")]
    public sealed class WindowsOpenSshPipeTests
    {
        private const string pipeName = "openssh-ssh-agent";
        private const string pipePath = "//./pipe/openssh-ssh-agent";

        [Test, NonParallelizable]
        public void TestMultipleInstancesThrowsException()
        {
            using (new WindowsOpenSshPipe((s, p) => { }))
            {
                Assert.That(
                    () => new WindowsOpenSshPipe((s2, p2) => { }),
                    Throws.TypeOf<PageantRunningException>()
                );
            }
        }

        [Test, NonParallelizable]
        public void TestThatServerStopsListeningWhenDisposed()
        {
            using (new WindowsOpenSshPipe((s, p) => { }))
            {
                Assert.That(File.Exists(pipePath), "Creating pipe should create socket file");
            }
            Assert.That(!File.Exists(pipePath), "Disposing pipe should remove file.");
        }

        [Test, NonParallelizable]
        public void TestThatSequentialConnectionsWork()
        {
            using (new WindowsOpenSshPipe((s, p) => { }))
            {
                using (var client = new NamedPipeClientStream(pipeName))
                {
                    client.Connect(1000);
                }
                using (var client = new NamedPipeClientStream(pipeName))
                {
                    client.Connect(1000);
                }
            }
        }

        [Test, NonParallelizable]
        public void TestThatDisposingWhileClientIsConnectedWorks()
        {
            var callbackEvent = new AutoResetEvent(false);

            using (
                var pipe = new WindowsOpenSshPipe(
                    (s, p) =>
                    {
                        s.ReadByte();
                        callbackEvent.Set();
                        s.ReadByte();
                        callbackEvent.Set();
                    }
                )
            )
            {
                using (var client = new NamedPipeClientStream(pipeName))
                {
                    client.Connect(1000);
                    client.WriteByte(0);
                    // have to wait for callback, otherwise we might dispose server
                    // before client connection is finished
                    callbackEvent.WaitOne(1000);
                    pipe.Dispose();
                    Assert.That(() => client.WriteByte(0), Throws.TypeOf<IOException>());
                }
            }
        }
    }
}
