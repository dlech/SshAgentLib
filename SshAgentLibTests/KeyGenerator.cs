//
// KeyGenerator.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013,2015,2022 David Lechner
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
using System.Text;

using dlech.SshAgentLib;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SshAgentLib.Keys;

namespace dlech.SshAgentLibTests
{
    public static class KeyGenerator
    {
        private static OpensshCertificateInfo CreateCertificate(
            AsymmetricKeyParameter publicKeyParams
        )
        {
            // build the certificate

            var publicKey = new SshKey(publicKeyParams);

            var certBuilder = new BlobBuilder();
            certBuilder.AddBlob(new byte[32]); // nonce

            if (publicKeyParams is RsaKeyParameters rsa)
            {
                certBuilder.AddBigIntBlob(rsa.Exponent);
                certBuilder.AddBigIntBlob(rsa.Modulus);
            }
            else if (publicKeyParams is DsaPublicKeyParameters dsa)
            {
                certBuilder.AddBigIntBlob(dsa.Parameters.P);
                certBuilder.AddBigIntBlob(dsa.Parameters.Q);
                certBuilder.AddBigIntBlob(dsa.Parameters.G);
                certBuilder.AddBigIntBlob(dsa.Y);
            }
            else if (publicKeyParams is ECPublicKeyParameters ecdsa)
            {
                certBuilder.AddStringBlob(publicKey.Algorithm.GetCurveDomainIdentifier());
                certBuilder.AddBlob(ecdsa.Q.GetEncoded());
            }
            else if (publicKeyParams is Ed25519PublicKeyParameters ed25519)
            {
                certBuilder.AddBlob(ed25519.GetEncoded());
            }
            else if (publicKeyParams is Ed448PublicKeyParameters ed448)
            {
                certBuilder.AddBlob(ed448.GetEncoded());
            }
            else
            {
                throw new ArgumentException("unknown algorithm", nameof(publicKeyParams));
            }

            const ulong serial = 0;
            const OpensshCertType type = OpensshCertType.User;
            const string keyId = "test key id";
            var principals = new string[] { "testtest" };
            var validAfter = DateTime.MinValue;
            var validBefore = DateTime.MaxValue;
            var criticalOptions = Array.Empty<byte>();
            var extensions = Array.Empty<byte>();
            var reserved = Array.Empty<byte>();
            // HACK: the signature key is really independent of publicKey - it
            // is the key used to sign the certificate by the CA and can even
            // use a different algorithm
            var signatureKey = new SshPublicKey(publicKey.GetPublicKeyBlob(false));
            var signature = Array.Empty<byte>();

            return new OpensshCertificateInfo(
                type,
                serial,
                keyId,
                principals,
                validAfter,
                validBefore,
                criticalOptions,
                extensions,
                reserved,
                signatureKey,
                signature
            );
        }

        /// <summary>
        /// Creates a random key for testing purposes.
        /// </summary
        /// <remarks>
        /// The <c>TEST_RANDOM_SEED</c> environment variable is used to seed the random number
        /// generator for repeatable tests.
        /// </remarks>
        /// <param name="version">The SSH key version.</param>
        /// <param name="algorithm">The SSH key signing algorithm.</param>
        /// <param name="comment">An optional comment.</param>
        /// <returns>The new key.</returns>
        /// <exception cref="Exception"></exception>
        public static SshKey CreateKey(PublicKeyAlgorithm algorithm, string comment = "")
        {
            var seed = Environment.GetEnvironmentVariable("TEST_RANDOM_SEED");
            var secureRandom = SecureRandom.GetInstance("SHA256PRNG");
            secureRandom.SetSeed(Encoding.Unicode.GetBytes(seed ?? "default"));

            var nonce = default(byte[]);
            var certificate = default(OpensshCertificateInfo);

            switch (algorithm)
            {
                case PublicKeyAlgorithm.SshRsa:
                case PublicKeyAlgorithm.SshRsaCertV1:
                    var keyGenParam = new KeyGenerationParameters(secureRandom, 512);

                    var rsaKeyPairGen = new RsaKeyPairGenerator();
                    rsaKeyPairGen.Init(keyGenParam);
                    var keyPair = rsaKeyPairGen.GenerateKeyPair();

                    if (algorithm.HasCert())
                    {
                        nonce = new byte[32];
                        certificate = CreateCertificate(keyPair.Public);
                    }

                    var rsaKey = new SshKey(keyPair, comment, nonce, certificate);
                    return rsaKey;

                case PublicKeyAlgorithm.SshDss:
                case PublicKeyAlgorithm.SshDssCertV1:
                    var dsaParamGen = new DsaParametersGenerator();
                    dsaParamGen.Init(512, 10, secureRandom);
                    var dsaParam = dsaParamGen.GenerateParameters();
                    var dsaKeyGenParam = new DsaKeyGenerationParameters(secureRandom, dsaParam);
                    var dsaKeyPairGen = new DsaKeyPairGenerator();
                    dsaKeyPairGen.Init(dsaKeyGenParam);
                    keyPair = dsaKeyPairGen.GenerateKeyPair();
                    var dsaKey = new SshKey(keyPair, comment, nonce, certificate);
                    return dsaKey;

                case PublicKeyAlgorithm.EcdsaSha2Nistp256:
                case PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1:
                    var ecdsa256X9Params = SecNamedCurves.GetByName("secp256r1");
                    var ecdsa256DomainParams = new ECDomainParameters(
                        ecdsa256X9Params.Curve,
                        ecdsa256X9Params.G,
                        ecdsa256X9Params.N,
                        ecdsa256X9Params.H
                    );
                    var ecdsa256GenParams = new ECKeyGenerationParameters(
                        ecdsa256DomainParams,
                        secureRandom
                    );
                    var ecdsa256Gen = new ECKeyPairGenerator();
                    ecdsa256Gen.Init(ecdsa256GenParams);
                    keyPair = ecdsa256Gen.GenerateKeyPair();

                    if (algorithm.HasCert())
                    {
                        nonce = new byte[32];
                        certificate = CreateCertificate(keyPair.Public);
                    }

                    var ecdsa256Key = new SshKey(keyPair, comment, nonce, certificate);
                    return ecdsa256Key;

                case PublicKeyAlgorithm.EcdsaSha2Nistp384:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384CertV1:
                    var ecdsa384X9Params = SecNamedCurves.GetByName("secp384r1");
                    var ecdsa384DomainParams = new ECDomainParameters(
                        ecdsa384X9Params.Curve,
                        ecdsa384X9Params.G,
                        ecdsa384X9Params.N,
                        ecdsa384X9Params.H
                    );
                    var ecdsa384GenParams = new ECKeyGenerationParameters(
                        ecdsa384DomainParams,
                        secureRandom
                    );
                    var ecdsa384Gen = new ECKeyPairGenerator();
                    ecdsa384Gen.Init(ecdsa384GenParams);
                    keyPair = ecdsa384Gen.GenerateKeyPair();

                    if (algorithm.HasCert())
                    {
                        nonce = new byte[32];
                        certificate = CreateCertificate(keyPair.Public);
                    }

                    var ecdsa384Key = new SshKey(keyPair, comment, nonce, certificate);
                    return ecdsa384Key;

                case PublicKeyAlgorithm.EcdsaSha2Nistp521:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521CertV1:
                    var ecdsa521X9Params = SecNamedCurves.GetByName("secp521r1");
                    var ecdsa521DomainParams = new ECDomainParameters(
                        ecdsa521X9Params.Curve,
                        ecdsa521X9Params.G,
                        ecdsa521X9Params.N,
                        ecdsa521X9Params.H
                    );
                    var ecdsa521GenParams = new ECKeyGenerationParameters(
                        ecdsa521DomainParams,
                        secureRandom
                    );
                    var ecdsa521Gen = new ECKeyPairGenerator();
                    ecdsa521Gen.Init(ecdsa521GenParams);
                    keyPair = ecdsa521Gen.GenerateKeyPair();

                    if (algorithm.HasCert())
                    {
                        nonce = new byte[32];
                        certificate = CreateCertificate(keyPair.Public);
                    }

                    var ecdsa521Key = new SshKey(keyPair, comment, nonce, certificate);
                    return ecdsa521Key;

                case PublicKeyAlgorithm.SshEd25519:
                case PublicKeyAlgorithm.SshEd25519CertV1:
                    var ed25519PrivateKey = new Ed25519PrivateKeyParameters(secureRandom);
                    var ed25519PublicKey = ed25519PrivateKey.GeneratePublicKey();
                    var ed25519Key = new SshKey(ed25519PublicKey, ed25519PrivateKey, comment, nonce, certificate);
                    return ed25519Key;

                case PublicKeyAlgorithm.SshEd448:
                case PublicKeyAlgorithm.SshEd448CertV1:
                    var ed448PrivateKey = new Ed448PrivateKeyParameters(secureRandom);
                    var ed448PublicKey = ed448PrivateKey.GeneratePublicKey();
                    var ed448Key = new SshKey(ed448PublicKey, ed448PrivateKey, comment, nonce, certificate);
                    return ed448Key;

                default:
                    throw new Exception("unsupported algorithm");
            }
        }
    }
}
