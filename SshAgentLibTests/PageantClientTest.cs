using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using NUnit.Framework;

using dlech.SshAgentLib;

namespace dlech.SshAgentLibTests
{
    [TestFixture, NonParallelizable]
    [Platform(Include = "Win")]
    public class PageantClientTest
    {

        [StructLayout(LayoutKind.Sequential)]
        struct COPYDATASTRUCT
        {
            public IntPtr dwData;
            public int cbData;
            public IntPtr lpData;
        }

        [Test, NonParallelizable]
        public void SendMessageTest()
        {
            if (Environment.GetEnvironmentVariable("CI") != null) {
              Assert.Ignore("SendMessage fails on CI");
            }

            // TODO: Need to modify this test so that it does not use PageantAgent
            const string messageValue = "junk";

            var builder = new BlobBuilder ();
            builder.AddStringBlob(messageValue);
            var messageBytes = builder.GetBlob();

            using (var agent = new PageantAgent()) {
                var client = new PageantClient();
                var reply = client.SendMessage(messageBytes);
                var replyParser = new BlobParser(reply);
                var replyHeader = replyParser.ReadHeader();
                Assert.That(replyHeader.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
            }
        }
    }
}
