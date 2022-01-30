//
// KeyGenerator.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013,2015 David Lechner
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
using Chaos.NaCl;
using dlech.SshAgentLib;
using dlech.SshAgentLib.Crypto;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace dlech.SshAgentLibTests
{
    public static class KeyGenerator
    {
        private static SecureRandom secureRandom;

        static KeyGenerator()
        {
            secureRandom = new SecureRandom();
        }

        public static SshKey CreateKey(
            SshVersion version,
            PublicKeyAlgorithm algorithm,
            string comment = ""
        )
        {
            if (version == SshVersion.SSH1 && algorithm != PublicKeyAlgorithm.SSH_RSA)
            {
                throw new Exception("unsupported version/algorithm combination");
            }

            switch (algorithm)
            {
                case PublicKeyAlgorithm.SSH_RSA:
                case PublicKeyAlgorithm.SSH_RSA_CERT_V1:
                    KeyGenerationParameters keyGenParam = new KeyGenerationParameters(
                        secureRandom,
                        512
                    );

                    var rsaKeyPairGen = new RsaKeyPairGenerator();
                    rsaKeyPairGen.Init(keyGenParam);
                    var keyPair = rsaKeyPairGen.GenerateKeyPair();
                    var rsaKey = new SshKey(version, keyPair, comment);
                    return rsaKey;

                case PublicKeyAlgorithm.SSH_DSS:
                case PublicKeyAlgorithm.SSH_DSS_CERT_V1:
                    DsaParametersGenerator dsaParamGen = new DsaParametersGenerator();
                    dsaParamGen.Init(512, 10, secureRandom);
                    DsaParameters dsaParam = dsaParamGen.GenerateParameters();
                    DsaKeyGenerationParameters dsaKeyGenParam = new DsaKeyGenerationParameters(
                        secureRandom,
                        dsaParam
                    );
                    DsaKeyPairGenerator dsaKeyPairGen = new DsaKeyPairGenerator();
                    dsaKeyPairGen.Init(dsaKeyGenParam);
                    keyPair = dsaKeyPairGen.GenerateKeyPair();
                    var dsaKey = new SshKey(SshVersion.SSH2, keyPair);
                    dsaKey.Comment = comment;
                    return dsaKey;

                case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
                case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V1:
                    X9ECParameters ecdsa256X9Params = SecNamedCurves.GetByName("secp256r1");
                    ECDomainParameters ecdsa256DomainParams = new ECDomainParameters(
                        ecdsa256X9Params.Curve,
                        ecdsa256X9Params.G,
                        ecdsa256X9Params.N,
                        ecdsa256X9Params.H
                    );
                    ECKeyGenerationParameters ecdsa256GenParams = new ECKeyGenerationParameters(
                        ecdsa256DomainParams,
                        secureRandom
                    );
                    ECKeyPairGenerator ecdsa256Gen = new ECKeyPairGenerator();
                    ecdsa256Gen.Init(ecdsa256GenParams);
                    keyPair = ecdsa256Gen.GenerateKeyPair();
                    var ecdsa256Key = new SshKey(SshVersion.SSH2, keyPair);
                    ecdsa256Key.Comment = comment;
                    return ecdsa256Key;

                case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
                case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V1:
                    X9ECParameters ecdsa384X9Params = SecNamedCurves.GetByName("secp384r1");
                    ECDomainParameters ecdsa384DomainParams = new ECDomainParameters(
                        ecdsa384X9Params.Curve,
                        ecdsa384X9Params.G,
                        ecdsa384X9Params.N,
                        ecdsa384X9Params.H
                    );
                    ECKeyGenerationParameters ecdsa384GenParams = new ECKeyGenerationParameters(
                        ecdsa384DomainParams,
                        secureRandom
                    );
                    ECKeyPairGenerator ecdsa384Gen = new ECKeyPairGenerator();
                    ecdsa384Gen.Init(ecdsa384GenParams);
                    keyPair = ecdsa384Gen.GenerateKeyPair();
                    var ecdsa384Key = new SshKey(SshVersion.SSH2, keyPair);
                    ecdsa384Key.Comment = comment;
                    return ecdsa384Key;

                case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
                case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V1:
                    X9ECParameters ecdsa521X9Params = SecNamedCurves.GetByName("secp521r1");
                    ECDomainParameters ecdsa521DomainParams = new ECDomainParameters(
                        ecdsa521X9Params.Curve,
                        ecdsa521X9Params.G,
                        ecdsa521X9Params.N,
                        ecdsa521X9Params.H
                    );
                    ECKeyGenerationParameters ecdsa521GenParams = new ECKeyGenerationParameters(
                        ecdsa521DomainParams,
                        secureRandom
                    );
                    ECKeyPairGenerator ecdsa521Gen = new ECKeyPairGenerator();
                    ecdsa521Gen.Init(ecdsa521GenParams);
                    keyPair = ecdsa521Gen.GenerateKeyPair();
                    var ecdsa521Key = new SshKey(SshVersion.SSH2, keyPair);
                    ecdsa521Key.Comment = comment;
                    return ecdsa521Key;

                case PublicKeyAlgorithm.ED25519:
                case PublicKeyAlgorithm.ED25519_CERT_V1:
                    var privateKeySeed = secureRandom.GenerateSeed(
                        Ed25519.PrivateKeySeedSizeInBytes
                    );
                    var publicKeyBytes = new byte[Ed25519.PublicKeySizeInBytes];
                    var privateKeyBytes = new byte[Ed25519.ExpandedPrivateKeySizeInBytes];
                    Ed25519.KeyPairFromSeed(
                        out publicKeyBytes,
                        out privateKeyBytes,
                        privateKeySeed
                    );
                    var publicKey = new Ed25519PublicKeyParameter(publicKeyBytes);
                    var privateKey = new Ed25519PrivateKeyParameter(privateKeyBytes);
                    var ed25519Key = new SshKey(SshVersion.SSH2, publicKey, privateKey, comment);
                    return ed25519Key;

                default:
                    throw new Exception("unsupported algorithm");
            }
        }
    }
}
