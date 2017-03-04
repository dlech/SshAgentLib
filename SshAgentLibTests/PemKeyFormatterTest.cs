//
// PemKeyFormatterTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2015 David Lechner
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

using System.IO;
using System.Security;

using NUnit.Framework;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using dlech.SshAgentLib;
using dlech.SshAgentLibTests.Properties;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    ///This is a test class for PemKeyFormatter and is intended
    ///to contain all PemKeyFormatter Unit Tests
    ///</summary>
    ///<remarks>
    ///Tests based on /src/regress/usr.bin/ssh/untistests/sshkey/test_file.c
    ///from OpenBSD source code.
    /// </remarks>
    [TestFixture]
    public class PemKeyFormatterTest
    {
        KeyFormatter.GetPassphraseCallback passphraseCallback;

        public PemKeyFormatterTest()
        {
            passphraseCallback = delegate(string comment)
            {
                SecureString passphrase = new SecureString();
                foreach (char c in Resources.pw.Trim()) {
                    passphrase.AppendChar(c);
                }
                return passphrase;
            };
        }

        [Test]
        public void TestDeserializeRsaFromPrivate()
        {
            var formatter = new PemKeyFormatter();
            var key = formatter.Deserialize(Resources.rsa_1);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));
            var publicKey = (RsaKeyParameters)key.GetPublicKeyParameters();
            var privateKey = (RsaPrivateCrtKeyParameters)key.GetPrivateKeyParameters();
            var param_n = new BigInteger(Resources.rsa_1_param_n.Trim(), 16);
            var param_p = new BigInteger(Resources.rsa_1_param_p.Trim(), 16);
            var param_q = new BigInteger(Resources.rsa_1_param_q.Trim(), 16);
            Assert.That(publicKey.Modulus, Is.EqualTo(param_n));
            Assert.That(privateKey.P, Is.EqualTo(param_p));
            Assert.That(privateKey.Q, Is.EqualTo(param_q));
        }

        [Test]
        public void TestDeserializeRsaFromPrivateWithPassphrase()
        {
            var formatter = new PemKeyFormatter();
            formatter.GetPassphraseCallbackMethod = passphraseCallback;
            var key = formatter.Deserialize(Resources.rsa_1_pw);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));
            var publicKey = (RsaKeyParameters)key.GetPublicKeyParameters();
            var privateKey = (RsaPrivateCrtKeyParameters)key.GetPrivateKeyParameters();
            var param_n = new BigInteger(Resources.rsa_1_param_n.Trim(), 16);
            var param_p = new BigInteger(Resources.rsa_1_param_p.Trim(), 16);
            var param_q = new BigInteger(Resources.rsa_1_param_q.Trim(), 16);
            Assert.That(publicKey.Modulus, Is.EqualTo(param_n));
            Assert.That(privateKey.P, Is.EqualTo(param_p));
            Assert.That(privateKey.Q, Is.EqualTo(param_q));
        }

        [Test]
        public void TestDeserializeDsaFromPrivate()
        {
            var formatter = new PemKeyFormatter();
            var key = formatter.Deserialize(Resources.dsa_1);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS));
            var publicKey = (DsaPublicKeyParameters)key.GetPublicKeyParameters();
            var privateKey = (DsaPrivateKeyParameters)key.GetPrivateKeyParameters();
            var param_g = new BigInteger(Resources.dsa_1_param_g.Trim(), 16);
            var param_priv = new BigInteger(Resources.dsa_1_param_priv.Trim(), 16);
            var param_pub = new BigInteger(Resources.dsa_1_param_pub.Trim(), 16);
            Assert.That(privateKey.Parameters.G, Is.EqualTo(param_g));
            Assert.That(privateKey.X, Is.EqualTo(param_priv));
            Assert.That(publicKey.Y, Is.EqualTo(param_pub));
        }

        [Test]
        public void TestDeserializeDsaFromPrivateWithPassphrase()
        {
            var formatter = new PemKeyFormatter();
            formatter.GetPassphraseCallbackMethod = passphraseCallback;
            var key = formatter.Deserialize(Resources.dsa_1_pw);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS));
            var publicKey = (DsaPublicKeyParameters)key.GetPublicKeyParameters();
            var privateKey = (DsaPrivateKeyParameters)key.GetPrivateKeyParameters();
            var param_g = new BigInteger(Resources.dsa_1_param_g.Trim(), 16);
            var param_priv = new BigInteger(Resources.dsa_1_param_priv.Trim(), 16);
            var param_pub = new BigInteger(Resources.dsa_1_param_pub.Trim(), 16);
            Assert.That(privateKey.Parameters.G, Is.EqualTo(param_g));
            Assert.That(privateKey.X, Is.EqualTo(param_priv));
            Assert.That(publicKey.Y, Is.EqualTo(param_pub));
        }

        [Test]
        public void TestDeserializeEcdsaFromPrivate()
        {
            var formatter = new PemKeyFormatter();
            var key = formatter.Deserialize(Resources.ecdsa_1);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP256));
            var publicKey = (ECPublicKeyParameters)key.GetPublicKeyParameters();
            var privateKey = (ECPrivateKeyParameters)key.GetPrivateKeyParameters();
            var param_curve = X962NamedCurves.GetByName(Resources.ecdsa_1_param_curve.Trim());
            var param_priv = new BigInteger(Resources.ecdsa_1_param_priv.Trim(), 16);
            var param_pub = new BigInteger(Resources.ecdsa_1_param_pub.Trim(), 16);
            Assert.That(privateKey.Parameters.Curve, Is.EqualTo(param_curve.Curve));
            Assert.That(privateKey.D, Is.EqualTo(param_priv));
            // TODO: figure out how to convert public key to BigInteger that matches param_pub
            //Assert.That(publicKey.Q, Is.EqualTo(param_pub));
        }

        [Test]
        public void TestDeserializeEcdsaFromPrivateWithPassphrase()
        {
            var formatter = new PemKeyFormatter();
            formatter.GetPassphraseCallbackMethod = passphraseCallback;
            var key = formatter.Deserialize(Resources.ecdsa_1_pw);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP256));
            var publicKey = (ECPublicKeyParameters)key.GetPublicKeyParameters();
            var privateKey = (ECPrivateKeyParameters)key.GetPrivateKeyParameters();
            var param_curve = X962NamedCurves.GetByName(Resources.ecdsa_1_param_curve.Trim());
            var param_priv = new BigInteger(Resources.ecdsa_1_param_priv.Trim(), 16);
            var param_pub = new BigInteger(Resources.ecdsa_1_param_pub.Trim(), 16);
            Assert.That(privateKey.Parameters.Curve, Is.EqualTo(param_curve.Curve));
            Assert.That(privateKey.D, Is.EqualTo(param_priv));
            // TODO: figure out how to convert public key to BigInteger that matches param_pub
            //Assert.That(publicKey.Q, Is.EqualTo(param_pub));
        }
    }
}
