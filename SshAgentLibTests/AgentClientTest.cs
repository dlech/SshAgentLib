// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2013,2015,2017,2022 David Lechner <david@lechnology.com>

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using dlech.SshAgentLib;
using dlech.SshAgentLibTests;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace SshAgentLibTests
{
    [TestFixture(typeof(MemoryStream))]
    [TestFixture(typeof(NonSeekableMemoryStream))]
    public class AgentClientTest<TStream> where TStream : MemoryStream
    {
        private static readonly SshKey rsaKey;
        private static readonly SshKey rsaCert;
        private static readonly SshKey dsaKey;
        private static readonly SshKey dsaCert;
        private static readonly SshKey ecdsa256Key;
        private static readonly SshKey ecdsa256Cert;
        private static readonly SshKey ecdsa384Key;
        private static readonly SshKey ecdsa384Cert;
        private static readonly SshKey ecdsa521Key;
        private static readonly SshKey ecdsa521Cert;
        private static readonly SshKey ed25519Key;
        private static readonly SshKey ed25519Cert;
        private static readonly ReadOnlyCollection<SshKey> allKeys;

        class TestAgentClient : AgentClient
        {
            public Agent Agent { get; private set; }

            public TestAgentClient()
            {
                Agent = new TestAgent();
            }

            public override byte[] SendMessage(byte[] message)
            {
                var buffer = new byte[4096];
                Array.Copy(message, buffer, message.Length);
                var messageStream = (TStream)Activator.CreateInstance(typeof(TStream), buffer);

                Agent.AnswerMessage(messageStream);

                // If the stream is seekable, it should have been rewound and
                // the reply written to the start of the buffer.
                if (messageStream.CanSeek)
                {
                    return buffer;
                }

                // Otherwise the reply is written to the buffer immediately
                // after the message.
                return new ArraySegment<byte>(
                    buffer,
                    message.Length,
                    buffer.Length - message.Length
                ).ToArray();
            }
        }

        class TestAgent : Agent
        {
            public override void Dispose() { }
        }

        static AgentClientTest()
        {
            rsaKey = KeyGenerator.CreateKey(PublicKeyAlgorithm.SshRsa, "SSH2 RSA test key");
            rsaCert = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.SshRsaCertV1,
                "SSH2 RSA test key + cert"
            );
            dsaKey = KeyGenerator.CreateKey(PublicKeyAlgorithm.SshDss, "SSH2 DSA test key");
            dsaCert = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.SshDssCertV1,
                "SSH2 DSA test key + cert"
            );
            ecdsa256Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp256,
                "SSH2 ECDSA 256 test key"
            );
            ecdsa256Cert = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1,
                "SSH2 ECDSA 256 test key + cert"
            );
            ecdsa384Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp384,
                "SSH2 ECDSA 384 test key"
            );
            ecdsa384Cert = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp384CertV1,
                "SSH2 ECDSA 384 test key + cert"
            );
            ecdsa521Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp521,
                "SSH2 ECDSA 521 test key"
            );
            ecdsa521Cert = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp521CertV1,
                "SSH2 ECDSA 521 test key + cert"
            );
            ed25519Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.SshEd25519,
                "SSH2 Ed25519 test key"
            );
            ed25519Cert = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.SshEd25519CertV1,
                "SSH2 Ed25519 test key + cert"
            );

            var keyList = new List<SshKey>
            {
                rsaKey,
                rsaCert,
                dsaKey,
                dsaCert,
                ecdsa256Key,
                ecdsa256Cert,
                ecdsa384Key,
                ecdsa384Cert,
                ecdsa521Key,
                ecdsa521Cert,
                ed25519Key,
                ed25519Cert
            };

            allKeys = keyList.AsReadOnly();
        }

        [Test]
        public void TestAddConstrainedKey()
        {
            var agentClient = new TestAgentClient();
            agentClient.Agent.ConfirmUserPermissionCallback = (k, p) => true;

            Agent.KeyConstraint constraint;
            var constraints = new List<Agent.KeyConstraint>();

            constraint = new Agent.KeyConstraint
            {
                Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM
            };

            constraints.Add(constraint);
            agentClient.AddKey(rsaKey, constraints);

            Assert.That(agentClient.Agent.KeyCount, Is.EqualTo(1));
            Assert.That(agentClient.Agent.ListKeys().First().Constraints.Count, Is.EqualTo(1));
            Assert.That(
                agentClient.Agent.ListKeys().First().Constraints.First().Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM)
            );

            constraint = new Agent.KeyConstraint
            {
                Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME,
                Data = (uint)10
            };

            constraints.Clear();
            constraints.Add(constraint);
            agentClient.AddKey(rsaKey, constraints);

            Assert.That(agentClient.Agent.KeyCount, Is.EqualTo(1));
            Assert.That(agentClient.Agent.ListKeys().First().Constraints.Count, Is.EqualTo(1));
            Assert.That(
                agentClient.Agent.ListKeys().First().Constraints.First().Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME)
            );
        }

        [Test]
        public void TestAddKey()
        {
            var agentClient = new TestAgentClient();
            var keyCount = 0;

            foreach (var key in allKeys)
            {
                agentClient.AddKey(key);
                keyCount += 1;
                Assert.That(agentClient.Agent.KeyCount, Is.EqualTo(keyCount));
                Assert.That(
                    agentClient.Agent.ListKeys().TryGet(key.GetPublicKeyBlob()),
                    Is.Not.Null,
                    $"{key.Algorithm.GetIdentifier()}"
                );
            }
        }

        [Test]
        public void TesListKeys()
        {
            var agentClient = new TestAgentClient();
            ICollection<ISshKey> keyList;

            foreach (var key in allKeys)
            {
                agentClient.Agent.AddKey(key);
            }

            // check that ssh2 keys worked
            keyList = agentClient.ListKeys();
            var expectedKeyList = allKeys.ToList();
            Assert.That(keyList.Count, Is.EqualTo(expectedKeyList.Count));
            foreach (var key in expectedKeyList)
            {
                Assert.That(
                    keyList.TryGet(key.GetPublicKeyBlob()),
                    Is.Not.Null,
                    $"{key.Algorithm.GetIdentifier()}"
                );
            }
        }

        [Test]
        public void TestRemoveAllKeys()
        {
            var agentClient = new TestAgentClient();

            /* test remove *all* keys */
            agentClient.Agent.AddKey(rsaKey);
            agentClient.Agent.AddKey(dsaKey);
            Assume.That(agentClient.Agent.KeyCount, Is.EqualTo(2));
            agentClient.RemoveAllKeys();
            Assert.That(agentClient.Agent.KeyCount, Is.EqualTo(0));
        }

        [Test]
        public void TestRemoveKey()
        {
            var agentClient = new TestAgentClient();

            /* test SSH2 */
            agentClient.Agent.AddKey(rsaKey);
            Assume.That(agentClient.Agent.KeyCount, Is.EqualTo(1));
            agentClient.RemoveKey(rsaKey);
            Assert.That(agentClient.Agent.KeyCount, Is.EqualTo(0));

            /* test key not found */
            agentClient.Agent.AddKey(rsaKey);
            Assume.That(agentClient.Agent.KeyCount, Is.EqualTo(1));
            Assert.That(
                () => agentClient.RemoveKey(dsaKey),
                Throws.TypeOf<AgentFailureException>()
            );
            Assert.That(agentClient.Agent.KeyCount, Is.EqualTo(1));
        }

        [Test]
        public void TestSignRequest()
        {
            var agentClient = new TestAgentClient();
            var data = Encoding.UTF8.GetBytes("Data to be signed");

            foreach (var key in allKeys)
            {
                agentClient.Agent.AddKey(key);
                var signature = agentClient.SignRequest(key, data);
                var signatureParser = new BlobParser(signature);
                var algorithm = signatureParser.ReadString();
                Assert.That(algorithm, Is.EqualTo(key.Algorithm.GetIdentifier()));
                signature = signatureParser.ReadBlob();

                if (key.Algorithm == PublicKeyAlgorithm.SshRsa)
                {
                    Assert.That(signature.Length == key.Size / 8);
                }
                else if (key.Algorithm == PublicKeyAlgorithm.SshDss)
                {
                    Assert.That(signature.Length, Is.EqualTo(40));

                    var r = new BigInteger(1, signature, 0, 20);
                    var s = new BigInteger(1, signature, 20, 20);
                    var seq = new DerSequence(new DerInteger(r), new DerInteger(s));
                    signature = seq.GetDerEncoded();
                }
                else if (
                    key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp256
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp384
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp521
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp384CertV1
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp521CertV1
                )
                {
                    Assert.That(signature.Length, Is.AtLeast(key.Size / 4 + 8));
                    Assert.That(signature.Length, Is.AtMost(key.Size / 4 + 10));

                    var parser = new BlobParser(signature);
                    var r = new BigInteger(parser.ReadBlob());
                    var s = new BigInteger(parser.ReadBlob());
                    var seq = new DerSequence(new DerInteger(r), new DerInteger(s));
                    signature = seq.GetDerEncoded();
                }

                var signer = key.GetSigner();
                signer.Init(false, key.GetPublicKeyParameters());
                signer.BlockUpdate(data, 0, data.Length);
                var valid = signer.VerifySignature(signature);

                Assert.That(valid, Is.True, $"{key.Algorithm.GetIdentifier()}");
            }
        }

        [Test]
        public void TestLockUnlock()
        {
            var passphrase = Encoding.UTF8.GetBytes("passphrase");
            var agentClient = new TestAgentClient();

            /* verify that locking works */
            Assert.That(() => agentClient.Lock(passphrase), Throws.Nothing);

            /* verify that locking already locked agent fails */
            Assert.That(
                () => agentClient.Lock(passphrase),
                Throws.Exception.TypeOf<AgentFailureException>()
            );

            /* verify that unlocking works */
            Assert.That(() => agentClient.Unlock(passphrase), Throws.Nothing);

            /* verify that unlocking already unlocked agent fails */
            Assert.That(
                () => agentClient.Unlock(passphrase),
                Throws.Exception.TypeOf<AgentFailureException>()
            );

            /* try with null passphrase */
            Assert.That(() => agentClient.Lock(null), Throws.ArgumentNullException);
            Assert.That(() => agentClient.Unlock(null), Throws.ArgumentNullException);

            /* verify that bad passphrase fails */
            Assert.That(() => agentClient.Lock(passphrase), Throws.Nothing);
            Assert.That(
                () => agentClient.Unlock(Array.Empty<byte>()),
                Throws.Exception.TypeOf<AgentFailureException>()
            );
        }
    }

    /// <summary>
    /// Memory stream with seek function disabled.
    /// </summary>
    /// <remarks>
    /// This is used to simulate an agent that uses a network stream
    /// that doesn't support seeking.
    /// </remarks>
    internal class NonSeekableMemoryStream : MemoryStream
    {
        public NonSeekableMemoryStream(byte[] buffer) : base(buffer) { }

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin loc)
        {
            throw new NotSupportedException();
        }
    }
}
