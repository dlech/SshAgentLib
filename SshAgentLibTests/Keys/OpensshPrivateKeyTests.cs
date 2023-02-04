// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2023 David Lechner <david@lechnology.com>

using System;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using SshAgentLib.Keys;
using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.Keys
{
    [TestFixture]
    public class OpensshPrivateKeyTests
    {
        [Test]
        public void TestThatReadingRsaPrivateKeyWorks()
        {
            var n = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.n");
            var p = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.p");
            var q = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.q");

            var file = OpenResourceFile("OpenSshTestData", "rsa_n");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<RsaKeyParameters>());

            var pubKey = (RsaKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));

            var privParam = key.Decrypt(null, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<RsaPrivateCrtKeyParameters>());
            Assert.That(comment, Is.Empty);

            var privKey = (RsaPrivateCrtKeyParameters)privParam;

            Assert.That(privKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));
            Assert.That(privKey.P, Is.EqualTo(new BigInteger(p, 16)));
            Assert.That(privKey.Q, Is.EqualTo(new BigInteger(q, 16)));

            // ensure that decrypting a second time works
            privParam = key.Decrypt(null, null, out comment);
            Assert.That(privParam.IsPrivate);
        }

        [Test]
        public void TestThatReadingRsaPrivateKeyWithPasswordWorks()
        {
            var n = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.n");
            var p = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.p");
            var q = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.q");
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var file = OpenResourceFile("OpenSshTestData", "rsa_n_pw");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<RsaKeyParameters>());

            var pubKey = (RsaKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));

            var privParam = key.Decrypt(() => Encoding.UTF8.GetBytes(pw), null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<RsaPrivateCrtKeyParameters>());
            Assert.That(comment, Is.Empty);

            var privKey = (RsaPrivateCrtKeyParameters)privParam;

            Assert.That(privKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));
            Assert.That(privKey.P, Is.EqualTo(new BigInteger(p, 16)));
            Assert.That(privKey.Q, Is.EqualTo(new BigInteger(q, 16)));

            // ensure that decrypting a second time works
            privParam = key.Decrypt(() => Encoding.UTF8.GetBytes(pw), null, out comment);
            Assert.That(privParam.IsPrivate);
        }

        [Test]
        public void TestThatReadingDsaPrivateKeyWorks()
        {
            var g = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.g");
            var priv = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.priv");
            var pub = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.pub");

            var file = OpenResourceFile("OpenSshTestData", "dsa_n");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

            var pubKey = (DsaPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Y, Is.EqualTo(new BigInteger(pub, 16)));

            var privParam = key.Decrypt(null, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<DsaPrivateKeyParameters>());
            Assert.That(comment, Is.Empty);

            var privKey = (DsaPrivateKeyParameters)privParam;

            Assert.That(privKey.Parameters.G, Is.EqualTo(new BigInteger(g, 16)));
            Assert.That(privKey.X, Is.EqualTo(new BigInteger(priv, 16)));
        }

        [Test]
        public void TestThatReadingDsaPrivateKeyWithPasswordWorks()
        {
            var g = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.g");
            var priv = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.priv");
            var pub = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.pub");
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var file = OpenResourceFile("OpenSshTestData", "dsa_n_pw");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

            var pubKey = (DsaPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Y, Is.EqualTo(new BigInteger(pub, 16)));

            var privParam = key.Decrypt(() => Encoding.UTF8.GetBytes(pw), null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<DsaPrivateKeyParameters>());
            Assert.That(comment, Is.Empty);

            var privKey = (DsaPrivateKeyParameters)privParam;

            Assert.That(privKey.Parameters.G, Is.EqualTo(new BigInteger(g, 16)));
            Assert.That(privKey.X, Is.EqualTo(new BigInteger(priv, 16)));
        }

        [Test]
        public void TestThatReadingEcdsaPrivateKeyWorks()
        {
            var curve = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.curve");
            var priv = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.priv");
            var pub = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.pub");

            var file = OpenResourceFile("OpenSshTestData", "ecdsa_n");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<ECPublicKeyParameters>());

            var pubKey = (ECPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(
                pubKey.Parameters.Curve,
                Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
            );
            Assert.That(pubKey.Q, Is.EqualTo(pubKey.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

            var privParam = key.Decrypt(null, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<ECPrivateKeyParameters>());
            Assert.That(comment, Is.Empty);

            var privKey = (ECPrivateKeyParameters)privParam;

            Assert.That(
                privKey.Parameters.Curve,
                Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
            );
            Assert.That(privKey.D, Is.EqualTo(new BigInteger(priv, 16)));
        }

        [Test]
        public void TestThatReadingEcdsaPrivateKeyWithPasswordWorks()
        {
            var curve = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.curve");
            var priv = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.priv");
            var pub = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.pub");
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var file = OpenResourceFile("OpenSshTestData", "ecdsa_n_pw");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<ECPublicKeyParameters>());

            var pubKey = (ECPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(
                pubKey.Parameters.Curve,
                Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
            );
            Assert.That(pubKey.Q, Is.EqualTo(pubKey.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

            var privParam = key.Decrypt(() => Encoding.UTF8.GetBytes(pw), null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<ECPrivateKeyParameters>());
            Assert.That(comment, Is.Empty);

            var privKey = (ECPrivateKeyParameters)privParam;

            Assert.That(privKey.D, Is.EqualTo(new BigInteger(priv, 16)));
        }

        [Test]
        public void TestThatReadingEd25519PrivateKeyWorks()
        {
            var file = OpenResourceFile("OpenSshTestData", "ed25519_1");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            var privParam = key.Decrypt(null, null, out var comment);
            Assert.That(comment, Is.EqualTo("ED25519 test key #1"));

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<Ed25519PrivateKeyParameters>());
        }

        [Test]
        public void TestThatReadingEd25519PrivateKeyWithPasswordWorks()
        {
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var file = OpenResourceFile("OpenSshTestData", "ed25519_1_pw");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            var privParam = key.Decrypt(() => Encoding.UTF8.GetBytes(pw), null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<Ed25519PrivateKeyParameters>());
            Assert.That(comment, Is.EqualTo("ED25519 test key #1"));
        }

        [Test]
        public void TestThatReadingEd25519PrivateKey2Works()
        {
            var file = OpenResourceFile("OpenSshTestData", "ed25519_2");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            var privParam = key.Decrypt(null, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<Ed25519PrivateKeyParameters>());
            // upstream file has typo
            Assert.That(comment, Is.EqualTo("ED25519 test key #1"));
        }
    }
}
