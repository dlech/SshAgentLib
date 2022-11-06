//
// AgentClient.cs
//
// Author(s): David Lechner <david@lechnology.com>
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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using SshAgentLib.Extension;

namespace dlech.SshAgentLib
{
    public abstract class AgentClient : IAgent
    {
        private byte[] mSessionId;

        /// <summary>
        /// Session ID used by SSH keys
        /// </summary>
        public byte[] SessionId
        {
            get
            {
                if (mSessionId == null)
                {
                    using (var md5 = MD5.Create())
                    {
                        md5.Initialize();
                        var currentProc = Process.GetCurrentProcess();
                        var sessionData = Encoding.UTF8.GetBytes(
                            currentProc.MachineName + currentProc.Id
                        );
                        mSessionId = md5.ComputeHash(sessionData);
                    }
                }
                return mSessionId;
            }
        }

        public event SshKeyEventHandler KeyAdded;

        public event SshKeyEventHandler KeyRemoved;

        /// <summary>
        /// Implementer should send the message to an SSH agent and return the reply
        /// </summary>
        /// <param name="aMessage">The message to send</param>
        /// <returns>The reply from the SSH agent</returns>
        public abstract byte[] SendMessage(byte[] aMessage);

        /// <summary>
        /// Adds key to SSH agent
        /// </summary>
        /// <param name="key">the key to add</param>
        /// <returns>true if operation was successful</returns>
        /// <remarks>applies constraints in aKeys.Constraints, if any</remarks>
        public void AddKey(ISshKey key)
        {
            AddKey(key, key.Constraints, key.DestinationConstraint);
        }

        /// <summary>
        /// Adds key to SSH agent
        /// </summary>
        /// <param name="key">the key to add</param>
        /// <param name="constraints">constraints to apply</param>
        /// <param name="destinationConstraint">destination constraint to apply</param>
        /// <returns>true if operation was successful</returns>
        /// <remarks>ignores constraints in key.Constraints</remarks>
        public void AddKey(
            ISshKey key,
            IEnumerable<Agent.KeyConstraint> constraints,
            DestinationConstraint destinationConstraint
        )
        {
            var builder = CreatePrivateKeyBlob(key);

            var isConstrained = false;

            if (constraints != null && constraints.Any())
            {
                isConstrained = true;

                foreach (var constraint in constraints)
                {
                    builder.AddUInt8((byte)constraint.Type);

                    // lifetime constraint has extra parameter
                    if (constraint.Type.GetDataType() == typeof(uint))
                    {
                        builder.AddUInt32((uint)constraint.Data);
                    }
                }
            }

            if (destinationConstraint != null)
            {
                isConstrained = true;

                builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_EXTENSION);
                builder.AddStringBlob(DestinationConstraint.ExtensionId);
                builder.AddBlob(destinationConstraint.ToBlob());
            }

            if (isConstrained)
            {
                builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
            }
            else
            {
                builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
            }

            SendMessageAndCheckSuccess(builder);
            FireKeyAdded(key);
        }

        /// <summary>
        /// Remove key from SSH agent
        /// </summary>
        /// <param name="key">The key to remove</param>
        /// <returns>true if removal succeeded</returns>
        public void RemoveKey(ISshKey key)
        {
            var builder = CreatePublicKeyBlob(key);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);

            SendMessageAndCheckSuccess(builder);
            FireKeyRemoved(key);
        }

        public void RemoveAllKeys()
        {
            var builder = new BlobBuilder();
            ICollection<ISshKey> keys = null;
            if (KeyRemoved != null)
            {
                keys = ListKeys();
            }

            builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);

            SendMessageAndCheckSuccess(builder);

            if (keys != null)
            {
                foreach (var key in keys)
                    FireKeyRemoved(key);
            }
        }

        public ICollection<ISshKey> ListKeys()
        {
            var builder = new BlobBuilder();

            builder.InsertHeader(Agent.Message.SSH2_AGENTC_REQUEST_IDENTITIES);

            var replyParser = SendMessage(builder);
            var keyCollection = new List<ISshKey>();
            var header = replyParser.ReadHeader();

            if (header.Message != Agent.Message.SSH2_AGENT_IDENTITIES_ANSWER)
            {
                throw new AgentFailureException();
            }
            var ssh2KeyCount = replyParser.ReadUInt32();
            for (var i = 0; i < ssh2KeyCount; i++)
            {
                var publicKeyBlob = replyParser.ReadBlob();
                var publicKeyParser = new BlobParser(publicKeyBlob);
                var publicKeyParams = publicKeyParser.ReadSsh2PublicKeyData(
                    out var nonce,
                    out var cert,
                    out var application
                );
                var comment = replyParser.ReadString();
                keyCollection.Add(
                    new SshKey(publicKeyParams, null, comment, nonce, cert, application)
                );
            }

            return keyCollection;
        }

        public byte[] SignRequest(ISshKey key, byte[] signData)
        {
            var builder = new BlobBuilder();

            builder.AddBlob(key.GetPublicKeyBlob());
            builder.AddBlob(signData);
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);

            var replyParser = SendMessage(builder);
            var header = replyParser.ReadHeader();

            if (header.Message != Agent.Message.SSH2_AGENT_SIGN_RESPONSE)
            {
                throw new AgentFailureException();
            }
            return replyParser.ReadBlob();
        }

        public void Lock(byte[] passphrase)
        {
            if (passphrase == null)
            {
                throw new ArgumentNullException(nameof(passphrase));
            }

            var builder = new BlobBuilder();
            builder.AddBlob(passphrase);
            builder.InsertHeader(Agent.Message.SSH_AGENTC_LOCK);
            SendMessageAndCheckSuccess(builder);
        }

        public void Unlock(byte[] passphrase)
        {
            if (passphrase == null)
            {
                throw new ArgumentNullException(nameof(passphrase));
            }

            var builder = new BlobBuilder();
            builder.AddBlob(passphrase);
            builder.InsertHeader(Agent.Message.SSH_AGENTC_UNLOCK);
            SendMessageAndCheckSuccess(builder);
        }

        private BlobBuilder CreatePublicKeyBlob(ISshKey key)
        {
            var builder = new BlobBuilder();

            builder.AddBlob(key.GetPublicKeyBlob());

            return builder;
        }

        private BlobParser SendMessage(BlobBuilder builder)
        {
            var reply = SendMessage(builder.GetBlob());

            try
            {
                return new BlobParser(reply);
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Sends message to remote agent and checks that it returned SSH_AGENT_SUCCESS
        /// </summary>
        /// <param name="aBuilder">The message to send</param>
        /// <exception cref="AgentFailureException">
        /// Thrown if agent did not return SSH_AGENT_SUCCESS
        /// </exception>
        private void SendMessageAndCheckSuccess(BlobBuilder aBuilder)
        {
            var replyParser = SendMessage(aBuilder);
            var header = replyParser.ReadHeader();
            if (header.Message != Agent.Message.SSH_AGENT_SUCCESS)
            {
                throw new AgentFailureException();
            }
        }

        BlobBuilder CreatePrivateKeyBlob(ISshKey key)
        {
            var builder = new BlobBuilder();

            builder.AddStringBlob(key.Algorithm.GetIdentifier());

            switch (key.Algorithm)
            {
                case PublicKeyAlgorithm.SshDss:
                    var dsaPublicKeyParameters =
                        key.GetPublicKeyParameters() as DsaPublicKeyParameters;
                    var dsaPrivateKeyParameters =
                        key.GetPrivateKeyParameters() as DsaPrivateKeyParameters;
                    builder.AddBigIntBlob(dsaPublicKeyParameters.Parameters.P);
                    builder.AddBigIntBlob(dsaPublicKeyParameters.Parameters.Q);
                    builder.AddBigIntBlob(dsaPublicKeyParameters.Parameters.G);
                    builder.AddBigIntBlob(dsaPublicKeyParameters.Y);
                    builder.AddBigIntBlob(dsaPrivateKeyParameters.X);
                    break;
                case PublicKeyAlgorithm.SshDssCertV1:

                    {
                        if (key.Certificate == null)
                        {
                            throw new ArgumentException(
                                "Certificate property cannot be null",
                                nameof(key)
                            );
                        }

                        builder.AddBlob(key.GetPublicKeyBlob());

                        var dsa = key.GetPrivateKeyParameters() as DsaPrivateKeyParameters;
                        builder.AddBigIntBlob(dsa.X);
                    }
                    break;
                case PublicKeyAlgorithm.EcdsaSha2Nistp256:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521:
                    var ecdsaPublicKeyParameters =
                        key.GetPublicKeyParameters() as ECPublicKeyParameters;
                    var ecdsaPrivateKeyParameters =
                        key.GetPrivateKeyParameters() as ECPrivateKeyParameters;
                    builder.AddStringBlob(key.Algorithm.GetCurveDomainIdentifier());
                    builder.AddBlob(ecdsaPublicKeyParameters.Q.GetEncoded());
                    builder.AddBigIntBlob(ecdsaPrivateKeyParameters.D);
                    break;
                case PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384CertV1:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521CertV1:
                    if (key.Certificate == null)
                    {
                        throw new ArgumentException(
                            "Certificate property cannot be null",
                            nameof(key)
                        );
                    }

                    builder.AddBlob(key.GetPublicKeyBlob());

                    var ecdsa = key.GetPrivateKeyParameters() as ECPrivateKeyParameters;
                    builder.AddBigIntBlob(ecdsa.D);
                    break;
                case PublicKeyAlgorithm.SshRsa:
                    var rsaPrivateKeyParameters =
                        key.GetPrivateKeyParameters() as RsaPrivateCrtKeyParameters;
                    builder.AddBigIntBlob(rsaPrivateKeyParameters.Modulus);
                    builder.AddBigIntBlob(rsaPrivateKeyParameters.PublicExponent);
                    builder.AddBigIntBlob(rsaPrivateKeyParameters.Exponent);
                    builder.AddBigIntBlob(rsaPrivateKeyParameters.QInv);
                    builder.AddBigIntBlob(rsaPrivateKeyParameters.P);
                    builder.AddBigIntBlob(rsaPrivateKeyParameters.Q);
                    break;
                case PublicKeyAlgorithm.SshRsaCertV1:

                    {
                        if (key.Certificate == null)
                        {
                            throw new ArgumentException(
                                "Certificate property cannot be null",
                                nameof(key)
                            );
                        }

                        builder.AddBlob(key.GetPublicKeyBlob());

                        var rsa = key.GetPrivateKeyParameters() as RsaPrivateCrtKeyParameters;
                        builder.AddBigIntBlob(rsa.Exponent);
                        builder.AddBigIntBlob(rsa.QInv);
                        builder.AddBigIntBlob(rsa.P);
                        builder.AddBigIntBlob(rsa.Q);
                    }
                    break;
                case PublicKeyAlgorithm.SshEd25519:
                    var ed25519PublicKeyParameters =
                        key.GetPublicKeyParameters() as Ed25519PublicKeyParameters;
                    var ed25519PrivateKeyParameters =
                        key.GetPrivateKeyParameters() as Ed25519PrivateKeyParameters;
                    var ed25519PublicKeyBytes = ed25519PublicKeyParameters.GetEncoded();
                    builder.AddBlob(ed25519PublicKeyBytes);
                    builder.AddBlob(
                        ed25519PrivateKeyParameters
                            .GetEncoded()
                            .Concat(ed25519PublicKeyBytes)
                            .ToArray()
                    );
                    break;
                case PublicKeyAlgorithm.SshEd25519CertV1:

                    {
                        if (key.Certificate == null)
                        {
                            throw new ArgumentException(
                                "Certificate property cannot be null",
                                nameof(key)
                            );
                        }

                        builder.AddBlob(key.GetPublicKeyBlob());

                        var ed25519Public =
                            key.GetPublicKeyParameters() as Ed25519PublicKeyParameters;
                        var ed25519Private =
                            key.GetPrivateKeyParameters() as Ed25519PrivateKeyParameters;
                        var ed25519PublicBytes = ed25519Public.GetEncoded();
                        builder.AddBlob(ed25519PublicBytes);
                        builder.AddBlob(
                            ed25519Private.GetEncoded().Concat(ed25519PublicBytes).ToArray()
                        );
                    }
                    break;
                default:
                    throw new Exception("Unsupported algorithm");
            }

            builder.AddStringBlob(key.Comment);

            return builder;
        }

        private void FireKeyAdded(ISshKey key)
        {
            if (KeyAdded != null)
            {
                var args = new SshKeyEventArgs(key);
                KeyAdded(this, args);
            }
        }

        private void FireKeyRemoved(ISshKey key)
        {
            if (KeyRemoved != null)
            {
                var args = new SshKeyEventArgs(key);
                KeyRemoved(this, args);
            }
        }
    }
}
