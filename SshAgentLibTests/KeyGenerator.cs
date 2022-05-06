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

namespace dlech.SshAgentLibTests
{
    public static class KeyGenerator
    {
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
        public static SshKey CreateKey(
            SshVersion version,
            PublicKeyAlgorithm algorithm,
            string comment = ""
        )
        {
            if (version == SshVersion.SSH1 && algorithm != PublicKeyAlgorithm.SshRsa)
            {
                throw new Exception("unsupported version/algorithm combination");
            }

            var seed = Environment.GetEnvironmentVariable("TEST_RANDOM_SEED");
            var secureRandom = SecureRandom.GetInstance("SHA256PRNG");
            secureRandom.SetSeed(Encoding.Unicode.GetBytes(seed ?? "default"));

            switch (algorithm)
            {
                case PublicKeyAlgorithm.SshRsa:
                case PublicKeyAlgorithm.SshRsaCertV1:
                    var keyGenParam = new KeyGenerationParameters(secureRandom, 512);

                    var rsaKeyPairGen = new RsaKeyPairGenerator();
                    rsaKeyPairGen.Init(keyGenParam);
                    var keyPair = rsaKeyPairGen.GenerateKeyPair();
                    var rsaKey = new SshKey(version, keyPair, comment);
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
                    var dsaKey = new SshKey(SshVersion.SSH2, keyPair, comment);
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
                    var ecdsa256Key = new SshKey(SshVersion.SSH2, keyPair, comment);
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
                    var ecdsa384Key = new SshKey(SshVersion.SSH2, keyPair, comment);
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
                    var ecdsa521Key = new SshKey(SshVersion.SSH2, keyPair, comment);
                    return ecdsa521Key;

                case PublicKeyAlgorithm.SshEd25519:
                case PublicKeyAlgorithm.SshEd25519CertV1:
                    var privateKey = new Ed25519PrivateKeyParameters(secureRandom);
                    var publicKey = privateKey.GeneratePublicKey();
                    var ed25519Key = new SshKey(SshVersion.SSH2, publicKey, privateKey, comment);
                    return ed25519Key;

                default:
                    throw new Exception("unsupported algorithm");
            }
        }
    }
}
