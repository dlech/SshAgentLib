//
// AgentTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013,2015,2017,2022 David Lechner
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


// Agent protocol is specified at http://api.libssh.org/rfc/PROTOCOL.agent
// Certificates are specified at http://api.libssh.org/rfc/PROTOCOL.certkeys

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using dlech.SshAgentLib;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SshAgentLib.Connection;
using SshAgentLib.Keys;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    ///This is a test class for Agent class and is intended
    ///to contain all Agent Unit Tests
    ///</summary>
    [TestFixture]
    public class AgentTest
    {
        /* instance variables */
        private static readonly byte[] buffer;
        private static readonly MemoryStream stream;
        private static readonly BlobParser parser;
        private static readonly SshKey rsaKey;
        private static readonly SshKey dsaKey;
        private static readonly SshKey ecdsa256Key;
        private static readonly SshKey ecdsa384Key;
        private static readonly SshKey ecdsa521Key;
        private static readonly SshKey ed25519Key;
        private static readonly ReadOnlyCollection<ISshKey> allKeys;

        // since Agent is an abstract class, we need to create a trivial
        // implementation
        private class TestAgent : Agent
        {
            public TestAgent() { }

            public TestAgent(IEnumerable<ISshKey> keyList)
            {
                foreach (var key in keyList)
                {
                    AddKey(key);
                }
            }

            public override void Dispose() { }
        }

        static AgentTest()
        {
            buffer = new byte[4096];
            stream = new MemoryStream(buffer);
            parser = new BlobParser(stream);

            rsaKey = KeyGenerator.CreateKey(PublicKeyAlgorithm.SshRsa, "SSH2 RSA test key");
            dsaKey = KeyGenerator.CreateKey(PublicKeyAlgorithm.SshDss, "SSH2 DSA test key");
            ecdsa256Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp256,
                "SSH2 ECDSA 256 test key"
            );
            ecdsa384Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp384,
                "SSH2 ECDSA 384 test key"
            );
            ecdsa521Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.EcdsaSha2Nistp521,
                "SSH2 ECDSA 521 test key"
            );
            ed25519Key = KeyGenerator.CreateKey(
                PublicKeyAlgorithm.SshEd25519,
                "SSH2 ED25519 test key"
            );

            allKeys = new List<ISshKey>
            {
                rsaKey,
                dsaKey,
                ecdsa256Key,
                ecdsa384Key,
                ecdsa521Key,
                ed25519Key
            }.AsReadOnly();
        }

        [Test]
        public void TestAnswerUnknownRequest()
        {
            Agent agent = new TestAgent();

            var unknownMessage = (byte)Agent.Message.UNKNOWN;
            Assert.That(unknownMessage, Is.Not.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
            PrepareSimpleMessage(unchecked((Agent.Message)unknownMessage));
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_RSA()
        {
            Agent agent = new TestAgent();
            var builder = new BlobBuilder();

            var rsaParameters = (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();
            builder.AddStringBlob(rsaKey.Algorithm.GetIdentifier());
            builder.AddBigIntBlob(rsaParameters.Modulus);
            builder.AddBigIntBlob(rsaParameters.PublicExponent);
            builder.AddBigIntBlob(rsaParameters.Exponent);
            builder.AddBigIntBlob(rsaParameters.QInv);
            builder.AddBigIntBlob(rsaParameters.P);
            builder.AddBigIntBlob(rsaParameters.Q);
            builder.AddStringBlob(rsaKey.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().First();
            Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<RsaKeyParameters>());
            Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<RsaKeyParameters>());
            Assert.That(returnedKey.Size, Is.EqualTo(rsaKey.Size));
            Assert.That(returnedKey.Comment, Is.EqualTo(rsaKey.Comment));
            Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(rsaKey.GetMD5Fingerprint()));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_RsaCert()
        {
            var rsaParameters = (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();

            var certBuilder = new BlobBuilder();
            certBuilder.AddStringBlob("ssh-rsa-cert-v01@openssh.com");
            certBuilder.AddBlob(new byte[32]); // nonce
            certBuilder.AddBigIntBlob(rsaParameters.PublicExponent); // e
            certBuilder.AddBigIntBlob(rsaParameters.Modulus); // n
            certBuilder.AddUInt64(0); // serial
            certBuilder.AddUInt32((uint)OpensshCertType.User); // type
            certBuilder.AddStringBlob("rsa-test-cert"); // key id
            certBuilder.AddBlob(Array.Empty<byte>()); // valid principals
            certBuilder.AddUInt64(0); // valid after
            certBuilder.AddUInt64(ulong.MaxValue); // valid before
            certBuilder.AddBlob(Array.Empty<byte>()); //critical options
            certBuilder.AddBlob(Array.Empty<byte>()); // extensions
            certBuilder.AddBlob(Array.Empty<byte>()); // reserved
            certBuilder.AddBlob(rsaKey.GetPublicKeyBlob()); // signature key
            certBuilder.AddBlob(Array.Empty<byte>()); // signature

            var builder = new BlobBuilder();
            builder.AddStringBlob("ssh-rsa-cert-v01@openssh.com");
            builder.AddBlob(certBuilder.GetBlob());
            builder.AddBigIntBlob(rsaParameters.Exponent); // D
            builder.AddBigIntBlob(rsaParameters.QInv);
            builder.AddBigIntBlob(rsaParameters.P);
            builder.AddBigIntBlob(rsaParameters.Q);
            builder.AddStringBlob(rsaKey.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

            PrepareMessage(builder);
            var agent = new TestAgent();
            agent.AnswerMessage(stream, new ConnectionContext());

            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().Single();
            Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<RsaKeyParameters>());
            Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<RsaKeyParameters>());
            Assert.That(returnedKey.Size, Is.EqualTo(rsaKey.Size));
            Assert.That(returnedKey.GetPublicKeyBlob(), Is.EqualTo(certBuilder.GetBlob()));
            Assert.That(returnedKey.Comment, Is.EqualTo(rsaKey.Comment));
            Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(rsaKey.GetMD5Fingerprint()));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_DSA()
        {
            var dsaPublicParameters = (DsaPublicKeyParameters)dsaKey.GetPublicKeyParameters();
            var dsaPrivateParameters = (DsaPrivateKeyParameters)dsaKey.GetPrivateKeyParameters();

            var builder = new BlobBuilder();
            builder.AddStringBlob(dsaKey.Algorithm.GetIdentifier());
            builder.AddBigIntBlob(dsaPublicParameters.Parameters.P);
            builder.AddBigIntBlob(dsaPublicParameters.Parameters.Q);
            builder.AddBigIntBlob(dsaPublicParameters.Parameters.G);
            builder.AddBigIntBlob(dsaPublicParameters.Y);
            builder.AddBigIntBlob(dsaPrivateParameters.X);
            builder.AddStringBlob(dsaKey.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

            PrepareMessage(builder);
            var agent = new TestAgent();
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().First();
            Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<DsaKeyParameters>());
            Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<DsaKeyParameters>());
            Assert.That(returnedKey.Size, Is.EqualTo(dsaKey.Size));
            Assert.That(returnedKey.Comment, Is.EqualTo(dsaKey.Comment));
            Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(dsaKey.GetMD5Fingerprint()));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_DsaCert()
        {
            var dsaPublicParameters = (DsaPublicKeyParameters)dsaKey.GetPublicKeyParameters();
            var dsaPrivateParameters = (DsaPrivateKeyParameters)dsaKey.GetPrivateKeyParameters();

            var certBuilder = new BlobBuilder();
            certBuilder.AddStringBlob("ssh-dss-cert-v01@openssh.com");
            certBuilder.AddBlob(new byte[32]); // nonce
            certBuilder.AddBigIntBlob(dsaPublicParameters.Parameters.P); // p
            certBuilder.AddBigIntBlob(dsaPublicParameters.Parameters.Q); // q
            certBuilder.AddBigIntBlob(dsaPublicParameters.Parameters.G); // g
            certBuilder.AddBigIntBlob(dsaPublicParameters.Y); // y
            certBuilder.AddUInt64(0); // serial
            certBuilder.AddUInt32((uint)OpensshCertType.User); // type
            certBuilder.AddStringBlob("dsa-test-cert"); // key id
            certBuilder.AddBlob(Array.Empty<byte>()); // valid principals
            certBuilder.AddUInt64(0); // valid after
            certBuilder.AddUInt64(ulong.MaxValue); // valid before
            certBuilder.AddBlob(Array.Empty<byte>()); //critical options
            certBuilder.AddBlob(Array.Empty<byte>()); // extensions
            certBuilder.AddBlob(Array.Empty<byte>()); // reserved
            certBuilder.AddBlob(dsaKey.GetPublicKeyBlob()); // signature key
            certBuilder.AddBlob(Array.Empty<byte>()); // signature

            var builder = new BlobBuilder();
            builder.AddStringBlob("ssh-dss-cert-v01@openssh.com");
            builder.AddBlob(certBuilder.GetBlob());
            builder.AddBigIntBlob(dsaPrivateParameters.X);
            builder.AddStringBlob(dsaKey.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

            PrepareMessage(builder);
            var agent = new TestAgent();
            agent.AnswerMessage(stream, new ConnectionContext());

            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().Single();
            Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<DsaKeyParameters>());
            Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<DsaKeyParameters>());
            Assert.That(returnedKey.Size, Is.EqualTo(dsaKey.Size));
            Assert.That(returnedKey.GetPublicKeyBlob(), Is.EqualTo(certBuilder.GetBlob()));
            Assert.That(returnedKey.Comment, Is.EqualTo(dsaKey.Comment));
            Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(dsaKey.GetMD5Fingerprint()));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_ECDSA()
        {
            var ecdsaKeysList = new List<ISshKey> { ecdsa256Key, ecdsa384Key, ecdsa521Key };

            foreach (var key in ecdsaKeysList)
            {
                var agent = new TestAgent();
                var builder = new BlobBuilder();

                var ecdsaPublicParameters = (ECPublicKeyParameters)key.GetPublicKeyParameters();
                var ecdsaPrivateParameters = (ECPrivateKeyParameters)key.GetPrivateKeyParameters();
                builder.AddStringBlob(key.Algorithm.GetIdentifier());
                builder.AddStringBlob(key.Algorithm.GetCurveDomainIdentifier());
                builder.AddBlob(ecdsaPublicParameters.Q.GetEncoded());
                builder.AddBigIntBlob(ecdsaPrivateParameters.D);
                builder.AddStringBlob(key.Comment);
                builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
                PrepareMessage(builder);
                agent.AnswerMessage(stream, new ConnectionContext());
                RewindStream();
                var header = parser.ReadHeader();
                Assert.That(header.BlobLength, Is.EqualTo(1));
                Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
                var returnedKey = agent.ListKeys().First();
                Assert.That(
                    returnedKey.GetPublicKeyParameters(),
                    Is.InstanceOf<ECPublicKeyParameters>()
                );
                Assert.That(
                    returnedKey.GetPrivateKeyParameters(),
                    Is.InstanceOf<ECPrivateKeyParameters>()
                );
                Assert.That(returnedKey.Size, Is.EqualTo(key.Size));
                Assert.That(returnedKey.Comment, Is.EqualTo(key.Comment));
                Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(key.GetMD5Fingerprint()));
                Assert.That(returnedKey.Constraints.Count, Is.EqualTo(0));
            }
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_EcdsaCert()
        {
            var ecdsaPublicParameters = (ECPublicKeyParameters)ecdsa256Key.GetPublicKeyParameters();
            var ecdsaPrivateParameters =
                (ECPrivateKeyParameters)ecdsa256Key.GetPrivateKeyParameters();

            var certBuilder = new BlobBuilder();
            certBuilder.AddStringBlob("ecdsa-sha2-nistp256-cert-v01@openssh.com");
            certBuilder.AddBlob(new byte[32]); // nonce
            certBuilder.AddStringBlob("nistp256"); // curve
            certBuilder.AddBlob(ecdsaPublicParameters.Q.GetEncoded()); // public key
            certBuilder.AddUInt64(0); // serial
            certBuilder.AddUInt32((uint)OpensshCertType.User); // type
            certBuilder.AddStringBlob("ecdsa-test-cert"); // key id
            certBuilder.AddBlob(Array.Empty<byte>()); // valid principals
            certBuilder.AddUInt64(0); // valid after
            certBuilder.AddUInt64(ulong.MaxValue); // valid before
            certBuilder.AddBlob(Array.Empty<byte>()); //critical options
            certBuilder.AddBlob(Array.Empty<byte>()); // extensions
            certBuilder.AddBlob(Array.Empty<byte>()); // reserved
            certBuilder.AddBlob(dsaKey.GetPublicKeyBlob()); // signature key
            certBuilder.AddBlob(Array.Empty<byte>()); // signature

            var builder = new BlobBuilder();
            builder.AddStringBlob("ecdsa-sha2-nistp256-cert-v01@openssh.com");
            builder.AddBlob(certBuilder.GetBlob());
            builder.AddBigIntBlob(ecdsaPrivateParameters.D);
            builder.AddStringBlob(ecdsa256Key.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

            PrepareMessage(builder);
            var agent = new TestAgent();
            agent.AnswerMessage(stream, new ConnectionContext());

            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().First();
            Assert.That(
                returnedKey.GetPublicKeyParameters(),
                Is.InstanceOf<ECPublicKeyParameters>()
            );
            Assert.That(
                returnedKey.GetPrivateKeyParameters(),
                Is.InstanceOf<ECPrivateKeyParameters>()
            );
            Assert.That(returnedKey.Size, Is.EqualTo(ecdsa256Key.Size));
            Assert.That(returnedKey.Comment, Is.EqualTo(ecdsa256Key.Comment));
            Assert.That(returnedKey.GetPublicKeyBlob(), Is.EqualTo(certBuilder.GetBlob()));
            Assert.That(
                returnedKey.GetMD5Fingerprint(),
                Is.EqualTo(ecdsa256Key.GetMD5Fingerprint())
            );
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(0));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_Ed25519()
        {
            var publicKeyParams = (Ed25519PublicKeyParameters)ed25519Key.GetPublicKeyParameters();
            var privateKeyParams =
                (Ed25519PrivateKeyParameters)ed25519Key.GetPrivateKeyParameters();

            var builder = new BlobBuilder();
            builder.AddStringBlob(ed25519Key.Algorithm.GetIdentifier());
            builder.AddBlob(publicKeyParams.GetEncoded());
            builder.AddBlob(privateKeyParams.GetEncoded());
            builder.AddStringBlob(ed25519Key.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

            PrepareMessage(builder);
            var agent = new TestAgent();
            agent.AnswerMessage(stream, new ConnectionContext());

            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().First();
            Assert.That(
                returnedKey.GetPublicKeyParameters(),
                Is.InstanceOf<Ed25519PublicKeyParameters>()
            );
            Assert.That(
                returnedKey.GetPrivateKeyParameters(),
                Is.InstanceOf<Ed25519PrivateKeyParameters>()
            );
            Assert.That(returnedKey.Size, Is.EqualTo(ed25519Key.Size));
            Assert.That(returnedKey.Comment, Is.EqualTo(ed25519Key.Comment));
            Assert.That(
                returnedKey.GetMD5Fingerprint(),
                Is.EqualTo(ed25519Key.GetMD5Fingerprint())
            );
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(0));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_Ed25519Cert()
        {
            var publicKeyParams = (Ed25519PublicKeyParameters)ed25519Key.GetPublicKeyParameters();
            var privateKeyParams =
                (Ed25519PrivateKeyParameters)ed25519Key.GetPrivateKeyParameters();

            var certBuilder = new BlobBuilder();
            certBuilder.AddStringBlob("ssh-ed25519-cert-v01@openssh.com");
            certBuilder.AddBlob(new byte[32]); // nonce
            certBuilder.AddBlob(publicKeyParams.GetEncoded()); // public key
            certBuilder.AddUInt64(0); // serial
            certBuilder.AddUInt32((uint)OpensshCertType.User); // type
            certBuilder.AddStringBlob("ed25519-test-cert"); // key id
            certBuilder.AddBlob(Array.Empty<byte>()); // valid principals
            certBuilder.AddUInt64(0); // valid after
            certBuilder.AddUInt64(ulong.MaxValue); // valid before
            certBuilder.AddBlob(Array.Empty<byte>()); //critical options
            certBuilder.AddBlob(Array.Empty<byte>()); // extensions
            certBuilder.AddBlob(Array.Empty<byte>()); // reserved
            certBuilder.AddBlob(ed25519Key.GetPublicKeyBlob()); // signature key
            certBuilder.AddBlob(Array.Empty<byte>()); // signature

            var builder = new BlobBuilder();
            builder.AddStringBlob("ssh-ed25519-cert-v01@openssh.com");
            builder.AddBlob(certBuilder.GetBlob());
            builder.AddBlob(publicKeyParams.GetEncoded());
            builder.AddBlob(privateKeyParams.GetEncoded());
            builder.AddStringBlob(ed25519Key.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

            PrepareMessage(builder);
            var agent = new TestAgent();
            agent.AnswerMessage(stream, new ConnectionContext());

            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().First();
            Assert.That(
                returnedKey.GetPublicKeyParameters(),
                Is.InstanceOf<Ed25519PublicKeyParameters>()
            );
            Assert.That(
                returnedKey.GetPrivateKeyParameters(),
                Is.InstanceOf<Ed25519PrivateKeyParameters>()
            );
            Assert.That(returnedKey.Size, Is.EqualTo(ed25519Key.Size));
            Assert.That(returnedKey.Comment, Is.EqualTo(ed25519Key.Comment));
            Assert.That(returnedKey.GetPublicKeyBlob(), Is.EqualTo(certBuilder.GetBlob()));
            Assert.That(
                returnedKey.GetMD5Fingerprint(),
                Is.EqualTo(ed25519Key.GetMD5Fingerprint())
            );
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(0));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_NoDuplicates()
        {
            var agent = new TestAgent();
            var builder = new BlobBuilder();

            var rsaParameters = (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();
            builder.AddStringBlob(rsaKey.Algorithm.GetIdentifier());
            builder.AddBigIntBlob(rsaParameters.Modulus);
            builder.AddBigIntBlob(rsaParameters.PublicExponent);
            builder.AddBigIntBlob(rsaParameters.Exponent);
            builder.AddBigIntBlob(rsaParameters.QInv);
            builder.AddBigIntBlob(rsaParameters.P);
            builder.AddBigIntBlob(rsaParameters.Q);
            builder.AddStringBlob(rsaKey.Comment);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());

            /* test adding key that already is in KeyList does not create duplicate */
            var startingCount = agent.ListKeys().Count;
            Assume.That(startingCount, Is.Not.EqualTo(0));
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            Assert.That(agent.ListKeys().Count, Is.EqualTo(startingCount));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_WhileLocked()
        {
            var agent = new TestAgent();
            var builder = new BlobBuilder();

            /* test locked => failure */
            agent.Lock(Array.Empty<byte>());
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
            Assert.That(agent.ListKeys().Count, Is.EqualTo(0));
        }

        [Test]
        public void TestAnswerSSH2_AGENTC_ADD_ID_CONSTRAINED()
        {
            /* most code is shared with SSH2_AGENTC_ADD_IDENTITY, so we just
             * need to test the differences */

            Agent.ConfirmUserPermissionDelegate confirmCallback = (k, p, u, f, t) =>
            {
                return true;
            };

            Agent agent = new TestAgent();

            /* test that no confirmation callback returns failure */

            var builder = new BlobBuilder();
            var rsaParameters = (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();
            builder.AddStringBlob(rsaKey.Algorithm.GetIdentifier());
            builder.AddBigIntBlob(rsaParameters.Modulus);
            builder.AddBigIntBlob(rsaParameters.PublicExponent);
            builder.AddBigIntBlob(rsaParameters.Exponent);
            builder.AddBigIntBlob(rsaParameters.QInv);
            builder.AddBigIntBlob(rsaParameters.P);
            builder.AddBigIntBlob(rsaParameters.Q);
            builder.AddStringBlob(rsaKey.Comment);
            //save blob so far so we don't have to repeat later.
            var commonBlob = builder.GetBlob();
            builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

            /* test adding key with confirm constraint */

            agent = new TestAgent { ConfirmUserPermissionCallback = confirmCallback };
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var returnedKey = agent.ListKeys().First();
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(1));
            Assert.That(
                returnedKey.Constraints[0].Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM)
            );
            Assert.That(returnedKey.Constraints[0].Data, Is.Null);

            /* test adding key with lifetime constraint */

            agent = new TestAgent();
            builder.Clear();
            builder.AddBytes(commonBlob);
            builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
            builder.AddInt(10);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            returnedKey = agent.ListKeys().First();
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(1));
            Assert.That(
                returnedKey.Constraints[0].Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME)
            );
            Assert.That(
                returnedKey.Constraints[0].Data.GetType(),
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME.GetDataType())
            );
            Assert.That(returnedKey.Constraints[0].Data, Is.EqualTo(10));

            /* test adding key with multiple constraints */

            agent = new TestAgent { ConfirmUserPermissionCallback = confirmCallback };
            builder.Clear();
            builder.AddBytes(commonBlob);
            builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
            builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
            builder.AddInt(10);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            returnedKey = agent.ListKeys().First();
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(2));
            Assert.That(
                returnedKey.Constraints[0].Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM)
            );
            Assert.That(returnedKey.Constraints[0].Data, Is.Null);
            Assert.That(
                returnedKey.Constraints[1].Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME)
            );
            Assert.That(returnedKey.Constraints[1].Data, Is.EqualTo(10));

            /* test adding key with multiple constraints in different order */

            agent = new TestAgent { ConfirmUserPermissionCallback = confirmCallback };
            builder.Clear();
            builder.AddBytes(commonBlob);
            builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
            builder.AddInt(10);
            builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            returnedKey = agent.ListKeys().First();
            Assert.That(returnedKey.Constraints.Count, Is.EqualTo(2));
            Assert.That(
                returnedKey.Constraints[0].Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME)
            );
            Assert.That(returnedKey.Constraints[0].Data, Is.EqualTo(10));
            Assert.That(
                returnedKey.Constraints[1].Type,
                Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM)
            );
            Assert.That(returnedKey.Constraints[1].Data, Is.Null);
        }

        [Test()]
        public void TestAnswerSSH2_AGENTC_REQUEST_IDENTITIES()
        {
            Agent agent = new TestAgent(allKeys);

            /* send request for SSH2 identities */
            PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REQUEST_IDENTITIES);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();

            /* check that we received proper response type */
            var header = parser.ReadHeader();
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH2_AGENT_IDENTITIES_ANSWER));

            /* check that we received the correct key count */
            var actualKeyCount = parser.ReadUInt32();
            var ssh2KeyList = agent.ListKeys().ToList();
            var expectedSsh2KeyCount = ssh2KeyList.Count;
            Assert.That(actualKeyCount, Is.EqualTo(expectedSsh2KeyCount));

            /* check that we have data for each key */
            for (var i = 0; i < actualKeyCount; i++)
            {
                var actualPublicKeyBlob = parser.ReadBlob();
                var expectedPublicKeyBlob = ssh2KeyList[i].GetPublicKeyBlob();
                Assert.That(actualPublicKeyBlob, Is.EqualTo(expectedPublicKeyBlob));
                var actualComment = parser.ReadString();
                var expectedComment = ssh2KeyList[i].Comment;
                Assert.That(actualComment, Is.EqualTo(expectedComment));
            }
            /* verify that the overall response length is correct */
            Assert.That(header.BlobLength, Is.EqualTo(stream.Position - 4));
        }

        [Test()]
        public void TestAnswerSSH2_AGENTC_SIGN_REQUEST()
        {
            const string signatureData = "this is the data that gets signed";
            var signatureDataBytes = Encoding.UTF8.GetBytes(signatureData);
            var builder = new BlobBuilder();

            Agent agent = new TestAgent(allKeys);
            Agent.BlobHeader header;
            byte[] signatureBlob;
            BlobParser signatureParser;
            string algorithm;
            byte[] signature;
            ISigner signer;
            bool signatureOk;
            BigInteger r,
                s;
            DerSequence seq;

            /* test signatures */

            foreach (var key in allKeys)
            {
                builder.Clear();
                builder.AddBlob(key.GetPublicKeyBlob());
                builder.AddStringBlob(signatureData);
                builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
                PrepareMessage(builder);
                agent.AnswerMessage(stream, new ConnectionContext());
                RewindStream();

                /* check that proper response type was received */
                header = parser.ReadHeader();
                Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
                signatureBlob = parser.ReadBlob();
                signatureParser = new BlobParser(signatureBlob);
                algorithm = signatureParser.ReadString();
                Assert.That(algorithm, Is.EqualTo(key.Algorithm.GetIdentifier()));
                signature = signatureParser.ReadBlob();
                if (key.Algorithm == PublicKeyAlgorithm.SshRsa)
                {
                    Assert.That(signature.Length == key.Size / 8);
                }
                else if (key.Algorithm == PublicKeyAlgorithm.SshDss)
                {
                    Assert.That(signature.Length, Is.EqualTo(40));
                    r = new BigInteger(1, signature, 0, 20);
                    s = new BigInteger(1, signature, 20, 20);
                    seq = new DerSequence(new DerInteger(r), new DerInteger(s));
                    signature = seq.GetDerEncoded();
                }
                else if (
                    key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp256
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp384
                    || key.Algorithm == PublicKeyAlgorithm.EcdsaSha2Nistp521
                )
                {
                    Assert.That(signature.Length, Is.AtLeast(key.Size / 4 + 8));
                    Assert.That(signature.Length, Is.AtMost(key.Size / 4 + 10));
                    var sigParser = new BlobParser(signature);
                    r = new BigInteger(sigParser.ReadBlob());
                    s = new BigInteger(sigParser.ReadBlob());
                    seq = new DerSequence(new DerInteger(r), new DerInteger(s));
                    signature = seq.GetDerEncoded();
                }
                else if (key.Algorithm == PublicKeyAlgorithm.SshEd25519)
                {
                    Assert.That(signature.Length, Is.EqualTo(64));
                }
                signer = key.GetSigner(out var _);
                signer.Init(false, key.GetPublicKeyParameters());
                signer.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
                signatureOk = signer.VerifySignature(signature);
                Assert.That(signatureOk, Is.True, "invalid signature");
                Assert.That(header.BlobLength, Is.EqualTo(stream.Position - 4));
            }

            /* test key not found */

            agent = new TestAgent();
            builder.Clear();
            builder.AddBlob(dsaKey.GetPublicKeyBlob());
            builder.AddStringBlob(signatureData);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header2 = parser.ReadHeader();
            Assert.That(header2.BlobLength, Is.EqualTo(1));
            Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

            /* test confirm constraint */

            agent = new TestAgent();
            var testConstraint = new Agent.KeyConstraint
            {
                Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM
            };
            var testKey = dsaKey.Clone();
            var confirmCallbackReturnValue = false;
            agent.ConfirmUserPermissionCallback = (k, p, u, f, t) =>
            {
                return confirmCallbackReturnValue;
            };
            testKey.AddConstraint(testConstraint);
            agent.AddKey(testKey);
            builder.Clear();
            builder.AddBlob(dsaKey.GetPublicKeyBlob());
            builder.AddStringBlob(signatureData);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header2 = parser.ReadHeader();
            Assert.That(header2.BlobLength, Is.EqualTo(1));
            Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
            confirmCallbackReturnValue = true;
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header2 = parser.ReadHeader();
            Assert.That(header2.BlobLength, Is.Not.EqualTo(1));
            Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
        }

        [Test()]
        public void TestAnswerSSH2_AGENTC_REMOVE_IDENTITY()
        {
            Agent agent = new TestAgent(allKeys);
            var builder = new BlobBuilder();

            /* test remove key returns success when key is removed */

            builder.AddBlob(rsaKey.GetPublicKeyBlob());
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            Assert.That(agent.ListKeys().SequenceEqual(allKeys.Where(key => key != rsaKey)));

            /* test remove key returns failure when key does not exist */

            var startCount = agent.ListKeys().Count;
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
            Assert.That(agent.ListKeys().Count, Is.EqualTo(startCount));

            /* test returns failure when locked */

            agent.Lock(Array.Empty<byte>());
            startCount = agent.ListKeys().Count;
            builder.AddBlob(dsaKey.GetPublicKeyBlob());
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
            PrepareMessage(builder);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
            Assert.That(agent.ListKeys().Count, Is.EqualTo(startCount));
        }

        [Test()]
        public void TestAnswerSSH2_AGENTC_REMOVE_ALL_IDENTITIES()
        {
            Agent agent = new TestAgent(allKeys);

            /* test that remove all keys removes keys */

            PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            var header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
            var actualKeyCount = agent.ListKeys().Count;
            Assert.That(actualKeyCount, Is.Zero);

            /* test that remove all keys returns success even when there are no keys */
            agent = new TestAgent();
            PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));

            /* test that returns failure when locked */
            agent.Lock(Array.Empty<byte>());
            PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            header = parser.ReadHeader();
            Assert.That(header.BlobLength, Is.EqualTo(1));
            Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
        }

        [Test()]
        public void TestAnswerSSH_AGENTC_LOCKandSSH_AGENTC_UNLOCK()
        {
            const string password = "password";

            Agent agent = new TestAgent();
            Assert.That(agent.IsLocked, Is.False, "Agent initial state was locked!");

            var agentLockedCalled = false;
            Agent.BlobHeader replyHeader;

            Agent.LockEventHandler agentLocked = (s, e) =>
            {
                Assert.That(
                    agentLockedCalled,
                    Is.False,
                    "LockEvent fired without resetting agentLockedCalled"
                );
                agentLockedCalled = true;
            };

            agent.Locked += agentLocked;

            /* test that unlock does nothing when already unlocked */

            PrepareLockMessage(false, password);
            agentLockedCalled = false;
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            replyHeader = parser.ReadHeader();
            Assert.That(
                replyHeader.Message,
                Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
                "Unlock should have failed because agent was already unlocked"
            );
            Assert.That(agent.IsLocked, Is.False, "Agent should still be unlocked");
            Assert.That(
                agentLockedCalled,
                Is.False,
                "agentLocked should not have been called because state did not change."
            );

            /* test that locking works */

            PrepareLockMessage(true, password);
            agentLockedCalled = false;
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            replyHeader = parser.ReadHeader();
            Assert.That(
                replyHeader.Message,
                Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS),
                "Locking should have succeeded"
            );
            Assert.That(agent.IsLocked, Is.True, "Agent should be locked");
            Assert.That(agentLockedCalled, Is.True, "agentLocked should have been called");

            /* test that trying to lock when already locked fails */

            PrepareLockMessage(true, password);
            agentLockedCalled = false;
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            replyHeader = parser.ReadHeader();
            Assert.That(
                replyHeader.Message,
                Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
                "Unlock should have failed because agent was already unlocked"
            );
            Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
            Assert.That(
                agentLockedCalled,
                Is.False,
                "agentLocked should not have been called because state did not change."
            );

            /* test that unlocking with wrong password fails */

            PrepareLockMessage(false, password + "x");
            agentLockedCalled = false;
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            replyHeader = parser.ReadHeader();
            Assert.That(
                replyHeader.Message,
                Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
                "Unlock should have failed because password was incorrect"
            );
            Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
            Assert.That(
                agentLockedCalled,
                Is.False,
                "agentLocked should not have been called because state did not change."
            );

            /* test that unlocking works */

            PrepareLockMessage(false, password);
            agentLockedCalled = false;
            agent.AnswerMessage(stream, new ConnectionContext());
            RewindStream();
            replyHeader = parser.ReadHeader();
            Assert.That(
                replyHeader.Message,
                Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS),
                "Unlock should have succeeded"
            );
            Assert.That(agent.IsLocked, Is.False, "Agent should be unlocked");
            Assert.That(agentLockedCalled, Is.True, "agentLocked should have been called");

            agent.Locked -= new Agent.LockEventHandler(agentLocked);
        }

        [Test()]
        public void TestOnKeyListChanged()
        {
            Agent agent = new TestAgent();

            /* test that key with lifetime constraint is automatically removed *
             * after lifetime expires */

            var keyPair = new AsymmetricCipherKeyPair(
                rsaKey.GetPublicKeyParameters(),
                rsaKey.GetPrivateKeyParameters()
            );
            ISshKey key = new SshKey(keyPair);
            var constraint = new Agent.KeyConstraint
            {
                Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME,
                Data = (uint)1
            };
            key.AddConstraint(constraint);
            agent.AddKey(key);
            Thread.Sleep(500);
            Assert.That(agent.ListKeys().Count, Is.EqualTo(1));
            Thread.Sleep(1000);
            Assert.That(agent.ListKeys().Count, Is.EqualTo(0));
        }

        #region helper methods

        /// <summary>
        /// writes BlobBuilder data to beginning of Stream and resets Stream
        /// </summary>
        private static void PrepareMessage(BlobBuilder builder)
        {
            ResetStream();
            stream.WriteBlob(builder);
            RewindStream();
        }

        /// <summary>
        /// prepares a message with no data
        /// </summary>
        private static void PrepareSimpleMessage(Agent.Message message)
        {
            var builder = new BlobBuilder();
            builder.InsertHeader(message);
            PrepareMessage(builder);
        }

        /// <summary>
        /// prepares a lock or unlock message with specified password
        /// </summary>
        private static void PrepareLockMessage(bool @lock, string password)
        {
            var builder = new BlobBuilder();
            builder.AddStringBlob(password);
            if (@lock)
            {
                builder.InsertHeader(Agent.Message.SSH_AGENTC_LOCK);
            }
            else
            {
                builder.InsertHeader(Agent.Message.SSH_AGENTC_UNLOCK);
            }
            PrepareMessage(builder);
        }

        private static void ResetStream()
        {
            Array.Clear(buffer, 0, buffer.Length);
            RewindStream();
        }

        private static void RewindStream()
        {
            stream.Position = 0;
        }
    }

    #endregion
}
