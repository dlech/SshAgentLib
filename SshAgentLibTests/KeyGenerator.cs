//
// KeyGenerator.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013 David Lechner
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
using dlech.SshAgentLib;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using dlech.SshAgentLib.Crypto;

namespace dlech.SshAgentLibTests
{
  public static class KeyGenerator
  {
    private static SecureRandom mSecureRandom;

    static KeyGenerator()
    {
      mSecureRandom = new SecureRandom();
    }

    public static SshKey CreateKey(SshVersion aVersion,
      PublicKeyAlgorithm aAlgorithm, string aComment = "")
    {      
      if (aVersion == SshVersion.SSH1 && 
        aAlgorithm != PublicKeyAlgorithm.SSH_RSA) {
        throw new Exception("unsupported version/algorithm combination");
      }

      switch (aAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          KeyGenerationParameters keyGenParam =
            new KeyGenerationParameters(mSecureRandom, 512);

          RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
          rsaKeyPairGen.Init(keyGenParam);
          AsymmetricCipherKeyPair keyPair = rsaKeyPairGen.GenerateKeyPair();
          var rsaKey = new SshKey(aVersion, keyPair);
          rsaKey.Comment = aComment;
          return rsaKey;

        case PublicKeyAlgorithm.SSH_DSS:
          DsaParametersGenerator dsaParamGen = new DsaParametersGenerator();
          dsaParamGen.Init(512, 10, mSecureRandom);
          DsaParameters dsaParam = dsaParamGen.GenerateParameters();
          DsaKeyGenerationParameters dsaKeyGenParam =
            new DsaKeyGenerationParameters(mSecureRandom, dsaParam);
          DsaKeyPairGenerator dsaKeyPairGen = new DsaKeyPairGenerator();
          dsaKeyPairGen.Init(dsaKeyGenParam);
          keyPair = dsaKeyPairGen.GenerateKeyPair();
          var dsaKey = new SshKey(SshVersion.SSH2, keyPair);
          dsaKey.Comment = aComment;
          return dsaKey;

        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
          X9ECParameters ecdsa256X9Params =
            SecNamedCurves.GetByName("secp256r1");
          ECDomainParameters ecdsa256DomainParams =
            new ECDomainParameters(ecdsa256X9Params.Curve, ecdsa256X9Params.G,
              ecdsa256X9Params.N, ecdsa256X9Params.H);
          ECKeyGenerationParameters ecdsa256GenParams =
            new ECKeyGenerationParameters(ecdsa256DomainParams, mSecureRandom);
          ECKeyPairGenerator ecdsa256Gen = new ECKeyPairGenerator();
          ecdsa256Gen.Init(ecdsa256GenParams);
          keyPair = ecdsa256Gen.GenerateKeyPair();
          var ecdsa256Key = new SshKey(SshVersion.SSH2, keyPair);
          ecdsa256Key.Comment = aComment;
          return ecdsa256Key;

        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
          X9ECParameters ecdsa384X9Params =
            SecNamedCurves.GetByName("secp384r1");
          ECDomainParameters ecdsa384DomainParams =
            new ECDomainParameters(ecdsa384X9Params.Curve, ecdsa384X9Params.G,
              ecdsa384X9Params.N, ecdsa384X9Params.H);
          ECKeyGenerationParameters ecdsa384GenParams =
            new ECKeyGenerationParameters(ecdsa384DomainParams, mSecureRandom);
          ECKeyPairGenerator ecdsa384Gen = new ECKeyPairGenerator();
          ecdsa384Gen.Init(ecdsa384GenParams);
          keyPair = ecdsa384Gen.GenerateKeyPair();
          var ecdsa384Key = new SshKey(SshVersion.SSH2, keyPair);
          ecdsa384Key.Comment = aComment;
          return ecdsa384Key;

        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
          X9ECParameters ecdsa521X9Params =
            SecNamedCurves.GetByName("secp521r1");
          ECDomainParameters ecdsa521DomainParams =
            new ECDomainParameters(ecdsa521X9Params.Curve, ecdsa521X9Params.G,
              ecdsa521X9Params.N, ecdsa521X9Params.H);
          ECKeyGenerationParameters ecdsa521GenParams =
            new ECKeyGenerationParameters(ecdsa521DomainParams, mSecureRandom);
          ECKeyPairGenerator ecdsa521Gen = new ECKeyPairGenerator();
          ecdsa521Gen.Init(ecdsa521GenParams);
          keyPair = ecdsa521Gen.GenerateKeyPair();
          var ecdsa521Key = new SshKey(SshVersion.SSH2, keyPair);
          ecdsa521Key.Comment = aComment;
          return ecdsa521Key;

        default:
          throw new Exception("unsupported algorithm");
      }
    }
  }
}
