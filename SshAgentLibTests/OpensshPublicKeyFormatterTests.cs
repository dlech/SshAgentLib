//
// OpensshPrivateKeyFormatterTest.cs
//
// Copyright (c) 2015 David Lechner
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
using System.Linq;
using dlech.SshAgentLib;
using dlech.SshAgentLib.Crypto;
using SshAgentLibTests.Properties;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLibTests
{
    [TestFixture]
    public class OpensshPublicKeyFormatterTests
    {
        static string FormatFingerprint(byte[] fp)
        {
            return "MD5:" + string.Join(":", fp.Select(x => string.Format("{0:x2}", x)));
        }

        [Test]
        public void TestDeserializeRsaPublicKey()
        {
            var keyFile = Resources.rsa_1_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));
            var publicKey = (RsaKeyParameters)key.GetPublicKeyParameters();
            var param_n = new BigInteger(Resources.rsa_1_param_n.Trim(), 16);
            Assert.That(publicKey.Modulus, Is.EqualTo(param_n));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.rsa_1_fp.Trim()));
        }

        [Test]
        public void TestDeserializeRsaPublicKeyCert()
        {
            var keyFile = Resources.rsa_1_cert_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA_CERT_V1));
            var publicKey = (RsaKeyParameters)key.GetPublicKeyParameters();
            var param_n = new BigInteger(Resources.rsa_1_param_n.Trim(), 16);
            Assert.That(publicKey.Modulus, Is.EqualTo(param_n));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.rsa_1_cert_fp.Trim()));

            var certSigningKey = (Ed25519PublicKeyParameter)key.Certificate.SignatureKey;
            var param_pub = new BigInteger(Resources.ed25519_1_param_pub.Trim(), 16);
            var k = new BigInteger(1, certSigningKey.Key);
            Assert.That(k, Is.EqualTo(param_pub));
            Assert.That(key.Certificate.Type, Is.EqualTo(Ssh2CertType.Host));
            Assert.That(key.Certificate.KeyId, Is.EqualTo("julius"));
            Assert.That(key.Certificate.Principals, Is.EquivalentTo(new[] { "host1", "host2" }));
            Assert.That(
                key.Certificate.ValidAfter,
                Is.EqualTo(new DateTime(1999, 1, 1).AddHours(-10))
            );
            Assert.That(
                key.Certificate.ValidBefore,
                Is.EqualTo(new DateTime(2011, 1, 1).AddHours(-10))
            );
            Assert.That(key.Certificate.Serial, Is.EqualTo(5));
        }

        [Test]
        public void TestDeserializeDsaPublicKey()
        {
            var keyFile = Resources.dsa_1_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS));
            var publicKey = (DsaPublicKeyParameters)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.dsa_1_param_pub.Trim(), 16);
            Assert.That(publicKey.Y, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.dsa_1_fp.Trim()));
        }

        [Test]
        public void TestDeserializeDsaPublicKeyCert()
        {
            var keyFile = Resources.dsa_1_cert_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS_CERT_V1));
            var publicKey = (DsaPublicKeyParameters)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.dsa_1_param_pub.Trim(), 16);
            Assert.That(publicKey.Y, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.dsa_1_fp.Trim()));

            var certSigningKey = (Ed25519PublicKeyParameter)key.Certificate.SignatureKey;
            var param_pub2 = new BigInteger(Resources.ed25519_1_param_pub.Trim(), 16);
            var k = new BigInteger(1, certSigningKey.Key);
            Assert.That(k, Is.EqualTo(param_pub2));
            Assert.That(key.Certificate.Type, Is.EqualTo(Ssh2CertType.Host));
            Assert.That(key.Certificate.KeyId, Is.EqualTo("julius"));
            Assert.That(key.Certificate.Principals, Is.EquivalentTo(new[] { "host1", "host2" }));
            Assert.That(
                key.Certificate.ValidAfter,
                Is.EqualTo(new DateTime(1999, 1, 1).AddHours(-10))
            );
            Assert.That(
                key.Certificate.ValidBefore,
                Is.EqualTo(new DateTime(2011, 1, 1).AddHours(-10))
            );
            Assert.That(key.Certificate.Serial, Is.EqualTo(6));
        }

        [Test]
        public void TestDeserializeEcdsaPublicKey()
        {
            var keyFile = Resources.ecdsa_1_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP256));
            var publicKey = (ECPublicKeyParameters)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.ecdsa_1_param_pub.Trim(), 16);
            var q = new BigInteger(publicKey.Q.GetEncoded());
            Assert.That(q, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.ecdsa_1_fp.Trim()));
        }

        [Test]
        public void TestDeserializeEcdsaPublicKeyCert()
        {
            var keyFile = Resources.ecdsa_1_cert_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V1));
            var publicKey = (ECPublicKeyParameters)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.ecdsa_1_param_pub.Trim(), 16);
            var q = new BigInteger(publicKey.Q.GetEncoded());
            Assert.That(q, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.ecdsa_1_fp.Trim()));

            var certSigningKey = (ECPublicKeyParameters)key.Certificate.SignatureKey;
            var q2 = new BigInteger(certSigningKey.Q.GetEncoded());
            Assert.That(q2, Is.EqualTo(param_pub));
            Assert.That(key.Certificate.Type, Is.EqualTo(Ssh2CertType.Host));
            Assert.That(key.Certificate.KeyId, Is.EqualTo("julius"));
            Assert.That(key.Certificate.Principals, Is.EquivalentTo(new[] { "host1", "host2" }));
            Assert.That(
                key.Certificate.ValidAfter,
                Is.EqualTo(new DateTime(1999, 1, 1).AddHours(-10))
            );
            Assert.That(
                key.Certificate.ValidBefore,
                Is.EqualTo(new DateTime(2011, 1, 1).AddHours(-10))
            );
            Assert.That(key.Certificate.Serial, Is.EqualTo(7));
        }

        [Test]
        public void TestDeserializeEcdsaPublicKey2()
        {
            var keyFile = Resources.ecdsa_2_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP521));
            var publicKey = (ECPublicKeyParameters)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.ecdsa_2_param_pub.Trim(), 16);
            var q = new BigInteger(publicKey.Q.GetEncoded());
            Assert.That(q, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.ecdsa_2_fp.Trim()));
        }

        [Test]
        public void TestDeserializeEd25519PublicKey()
        {
            var keyFile = Resources.ed25519_1_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ED25519));
            var publicKey = (Ed25519PublicKeyParameter)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.ed25519_1_param_pub.Trim(), 16);
            var k = new BigInteger(1, publicKey.Key);
            Assert.That(k, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.ed25519_1_fp.Trim()));
        }

        [Test]
        public void TestDeserializeEd25519PublicKeyCert()
        {
            var keyFile = Resources.ed25519_1_cert_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ED25519_CERT_V1));
            var publicKey = (Ed25519PublicKeyParameter)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.ed25519_1_param_pub.Trim(), 16);
            var k = new BigInteger(1, publicKey.Key);
            Assert.That(k, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.ed25519_1_fp.Trim()));

            var certSigningKey = (Ed25519PublicKeyParameter)key.Certificate.SignatureKey;
            var param_pub2 = new BigInteger(Resources.ed25519_1_param_pub.Trim(), 16);
            var k2 = new BigInteger(1, certSigningKey.Key);
            Assert.That(k2, Is.EqualTo(param_pub2));
            Assert.That(key.Certificate.Type, Is.EqualTo(Ssh2CertType.Host));
            Assert.That(key.Certificate.KeyId, Is.EqualTo("julius"));
            Assert.That(key.Certificate.Principals, Is.EquivalentTo(new[] { "host1", "host2" }));
            Assert.That(
                key.Certificate.ValidAfter,
                Is.EqualTo(new DateTime(1999, 1, 1).AddHours(-10))
            );
            Assert.That(
                key.Certificate.ValidBefore,
                Is.EqualTo(new DateTime(2011, 1, 1).AddHours(-10))
            );
            Assert.That(key.Certificate.Serial, Is.EqualTo(8));
        }

        [Test]
        public void TestDeserializeEd25519PublicKey2()
        {
            var keyFile = Resources.ed25519_2_pub;
            var formatter = new OpensshPublicKeyFormatter();
            var key = formatter.Deserialize(keyFile);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ED25519));
            var publicKey = (Ed25519PublicKeyParameter)key.GetPublicKeyParameters();
            var param_pub = new BigInteger(Resources.ed25519_2_param_pub.Trim(), 16);
            var k = new BigInteger(1, publicKey.Key);
            Assert.That(k, Is.EqualTo(param_pub));
            var fp = FormatFingerprint(key.GetMD5Fingerprint());
            Assert.That(fp, Is.EqualTo(Resources.ed25519_2_fp.Trim()));
        }
    }
}
