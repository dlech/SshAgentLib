// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.Security;
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
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<RsaKeyParameters>());

            var pubKey = (RsaKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));

            key.Decrypt(null);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<RsaPrivateCrtKeyParameters>());

            var privKey = (RsaPrivateCrtKeyParameters)key.PrivateKey;

            Assert.That(privKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));
            Assert.That(privKey.P, Is.EqualTo(new BigInteger(p, 16)));
            Assert.That(privKey.Q, Is.EqualTo(new BigInteger(q, 16)));

            key.Encrypt();
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);
            key.Decrypt(null);
            Assert.That(key.PrivateKey.IsPrivate);
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

            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            var passphrase = new SecureString();

            foreach (var c in pw)
            {
                passphrase.AppendChar(c);
            }

            key.Decrypt((_) => passphrase);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<RsaPrivateCrtKeyParameters>());

            var privKey = (RsaPrivateCrtKeyParameters)key.PrivateKey;

            Assert.That(privKey.Modulus, Is.EqualTo(new BigInteger(n, 16)));
            Assert.That(privKey.P, Is.EqualTo(new BigInteger(p, 16)));
            Assert.That(privKey.Q, Is.EqualTo(new BigInteger(q, 16)));

            key.Encrypt();
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);
            key.Decrypt((_) => passphrase);
            Assert.That(key.PrivateKey.IsPrivate);
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
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

            var pubKey = (DsaPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Y, Is.EqualTo(new BigInteger(pub, 16)));

            key.Decrypt(null);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<DsaPrivateKeyParameters>());

            var privKey = (DsaPrivateKeyParameters)key.PrivateKey;

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
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

            var pubKey = (DsaPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Y, Is.EqualTo(new BigInteger(pub, 16)));

            var passphrase = new SecureString();

            foreach (var c in pw)
            {
                passphrase.AppendChar(c);
            }

            key.Decrypt((_) => passphrase);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<DsaPrivateKeyParameters>());

            var privKey = (DsaPrivateKeyParameters)key.PrivateKey;

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
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<ECPublicKeyParameters>());

            var pubKey = (ECPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(
                pubKey.Parameters.Curve,
                Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
            );
            Assert.That(pubKey.Q, Is.EqualTo(pubKey.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

            key.Decrypt(null);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<ECPrivateKeyParameters>());

            var privKey = (ECPrivateKeyParameters)key.PrivateKey;

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
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<ECPublicKeyParameters>());

            var pubKey = (ECPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(
                pubKey.Parameters.Curve,
                Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
            );
            Assert.That(pubKey.Q, Is.EqualTo(pubKey.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

            var passphrase = new SecureString();

            foreach (var c in pw)
            {
                passphrase.AppendChar(c);
            }

            key.Decrypt((_) => passphrase);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<ECPrivateKeyParameters>());

            var privKey = (ECPrivateKeyParameters)key.PrivateKey;

            Assert.That(privKey.D, Is.EqualTo(new BigInteger(priv, 16)));
        }

        [Test]
        public void TestThatReadingEd25519PrivateKeyWorks()
        {
            var file = OpenResourceFile("OpenSshTestData", "ed25519_1");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            key.Decrypt(null);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<Ed25519PrivateKeyParameters>());
        }

        [Test]
        public void TestThatReadingEd25519PrivateKeyWithPasswordWorks()
        {
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var file = OpenResourceFile("OpenSshTestData", "ed25519_1_pw");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            var passphrase = new SecureString();

            foreach (var c in pw)
            {
                passphrase.AppendChar(c);
            }

            key.Decrypt((_) => passphrase);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<Ed25519PrivateKeyParameters>());
        }

        [Test]
        public void TestThatReadingEd25519PrivateKey2Works()
        {
            var file = OpenResourceFile("OpenSshTestData", "ed25519_2");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());
            Assert.That(() => key.PrivateKey, Throws.InvalidOperationException);

            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            key.Decrypt(null);

            Assert.That(key.PrivateKey.IsPrivate);
            Assert.That(key.PrivateKey, Is.TypeOf<Ed25519PrivateKeyParameters>());
        }
    }
}
