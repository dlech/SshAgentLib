//
// SshKey.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2015,2017,2022 David Lechner
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
using System.Collections.ObjectModel;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using SshAgentLib.Extension;
using SshAgentLib.Keys;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Class for encapsulating information on encryption keys so that it can be
    /// used in PuTTY related programs
    /// </summary>
    public class SshKey : ISshKey
    {
        private readonly List<Agent.KeyConstraint> keyConstraints;
        private readonly AsymmetricKeyParameter publicKeyParameter;
        private readonly AsymmetricKeyParameter privateKeyParameter;

        public SshKey(
            AsymmetricKeyParameter publicKeyParameter,
            AsymmetricKeyParameter privateKeyParameter = null,
            string comment = "",
            byte[] nonce = null,
            OpensshCertificateInfo certificate = null,
            string application = null
        )
        {
            IsPublicOnly = privateKeyParameter == null;
            this.publicKeyParameter =
                publicKeyParameter ?? throw new ArgumentNullException(nameof(publicKeyParameter));
            this.privateKeyParameter = privateKeyParameter;

            Comment = comment ?? throw new ArgumentNullException(nameof(comment));
            Nonce = nonce;
            Certificate = certificate;
            Application = application;

            if ((nonce == null && certificate != null) || (nonce != null && certificate == null))
            {
                throw new ArgumentException(
                    "nonce cannot be null if and only if certificate is not null"
                );
            }

            keyConstraints = new List<Agent.KeyConstraint>();
        }

        public SshKey(
            AsymmetricCipherKeyPair cipherKeyPair,
            string comment = "",
            byte[] nonce = null,
            OpensshCertificateInfo certificate = null,
            string application = null
        )
            : this(
                cipherKeyPair.Public,
                cipherKeyPair.Private,
                comment,
                nonce,
                certificate,
                application
            ) { }

        public PublicKeyAlgorithm Algorithm
        {
            get
            {
                if (publicKeyParameter is RsaKeyParameters)
                {
                    if (Certificate != null)
                    {
                        return PublicKeyAlgorithm.SshRsaCertV1;
                    }
                    return PublicKeyAlgorithm.SshRsa;
                }
                else if (publicKeyParameter is DsaPublicKeyParameters)
                {
                    if (Certificate != null)
                    {
                        return PublicKeyAlgorithm.SshDssCertV1;
                    }
                    return PublicKeyAlgorithm.SshDss;
                }
                else if (publicKeyParameter is ECPublicKeyParameters ecdsaParameters)
                {
                    switch (ecdsaParameters.Q.Curve.FieldSize)
                    {
                        case 256:
                            if (Certificate != null)
                            {
                                if (Application != null)
                                {
                                    return PublicKeyAlgorithm.SkEcdsaSha2Nistp256CertV1;
                                }

                                return PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1;
                            }

                            if (Application != null)
                            {
                                return PublicKeyAlgorithm.SkEcdsaSha2Nistp256;
                            }

                            return PublicKeyAlgorithm.EcdsaSha2Nistp256;
                        case 384:
                            if (Certificate != null)
                            {
                                if (Application != null)
                                {
                                    return PublicKeyAlgorithm.SkEcdsaSha2Nistp384CertV1;
                                }

                                return PublicKeyAlgorithm.EcdsaSha2Nistp384CertV1;
                            }

                            if (Application != null)
                            {
                                return PublicKeyAlgorithm.SkEcdsaSha2Nistp384;
                            }

                            return PublicKeyAlgorithm.EcdsaSha2Nistp384;
                        case 521:
                            if (Certificate != null)
                            {
                                if (Application != null)
                                {
                                    return PublicKeyAlgorithm.SkEcdsaSha2Nistp521CertV1;
                                }

                                return PublicKeyAlgorithm.EcdsaSha2Nistp521CertV1;
                            }

                            if (Application != null)
                            {
                                return PublicKeyAlgorithm.SkEcdsaSha2Nistp521;
                            }

                            return PublicKeyAlgorithm.EcdsaSha2Nistp521;
                    }
                }
                else if (publicKeyParameter is Ed25519PublicKeyParameters)
                {
                    if (Certificate != null)
                    {
                        if (Application != null)
                        {
                            return PublicKeyAlgorithm.SkSshEd25519CertV1;
                        }

                        return PublicKeyAlgorithm.SshEd25519CertV1;
                    }

                    if (Application != null)
                    {
                        return PublicKeyAlgorithm.SkSshEd25519;
                    }

                    return PublicKeyAlgorithm.SshEd25519;
                }
                throw new Exception("Unknown algorithm");
            }
        }

        public byte[] Nonce { get; }

        public OpensshCertificateInfo Certificate { get; }

        public string Application { get; }

        public bool IsPublicOnly { get; }

        public int Size
        {
            get
            {
                if (publicKeyParameter is RsaKeyParameters)
                {
                    var rsaKeyParameters = (RsaKeyParameters)publicKeyParameter;
                    return rsaKeyParameters.Modulus.BitLength;
                }
                else if (publicKeyParameter is DsaPublicKeyParameters)
                {
                    var dsaKeyParameters = (DsaPublicKeyParameters)publicKeyParameter;
                    return dsaKeyParameters.Parameters.P.BitLength;
                }
                else if (publicKeyParameter is ECPublicKeyParameters)
                {
                    var ecdsaParameters = (ECPublicKeyParameters)publicKeyParameter;
                    return ecdsaParameters.Q.Curve.FieldSize;
                }
                else if (publicKeyParameter is Ed25519PublicKeyParameters)
                {
                    return 255;
                }
                // TODO need a better exception here
                throw new Exception("Not Defined");
            }
        }

        /// <summary>
        /// User comment
        /// </summary>
        public string Comment { get; set; }

        /// <summary>
        /// Source of the key file
        /// </summary>
        public string Source { get; set; }

        public ReadOnlyCollection<Agent.KeyConstraint> Constraints
        {
            get { return keyConstraints.AsReadOnly(); }
        }

        public DestinationConstraint DestinationConstraint { get; set; }

        public AsymmetricKeyParameter GetPublicKeyParameters()
        {
            return publicKeyParameter;
        }

        public AsymmetricKeyParameter GetPrivateKeyParameters()
        {
            return privateKeyParameter;
        }

        public void AddConstraint(Agent.KeyConstraint aConstraint)
        {
            if (
                (aConstraint.Data == null && aConstraint.Type.GetDataType() != null)
                || (
                    aConstraint.Data != null
                    && aConstraint.Data.GetType() != aConstraint.Type.GetDataType()
                )
            )
            {
                throw new ArgumentException("Malformed constraint", "aConstraint");
            }
            keyConstraints.Add(aConstraint);
        }

        ~SshKey()
        {
            this.Dispose();
        }

        public void Dispose()
        {
            // TODO is there a way to clear parameters from memory?
        }

        public SshKey Clone()
        {
            var keyPair = new AsymmetricCipherKeyPair(
                GetPublicKeyParameters(),
                GetPrivateKeyParameters()
            );

            var newKey = new SshKey(keyPair, Comment) { Source = Source };

            foreach (var constraint in keyConstraints)
            {
                newKey.AddConstraint(constraint);
            }

            return newKey;
        }
    }
}
