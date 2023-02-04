// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2023 David Lechner <david@lechnology.com>

using System;
using System.Text;
using dlech.SshAgentLib;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SshAgentLib.Keys;
using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.Keys
{
    [TestFixture]
    public class PuttyPrivateKeyTests
    {
        [TestCase("v2", "none", null)]
        [TestCase("v2", "aes256cbc", null)]
        [TestCase("v3", "none", "none")]
        [TestCase("v3", "aes256cbc", "argon2id")]
        public void TestThatReadingRsaKeyWorks(
            string version,
            string encryption,
            string keyDerivation
        )
        {
            var n = ReadStringResourceFile("PuttyTestData", "rsa.param.n");
            var p = ReadStringResourceFile("PuttyTestData", "rsa.param.p");
            var q = ReadStringResourceFile("PuttyTestData", "rsa.param.q");

            var kdf = keyDerivation == null ? string.Empty : $"-{keyDerivation}";
            var file = OpenResourceFile("PuttyTestData", $"rsa-{version}-{encryption}{kdf}.ppk");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<RsaKeyParameters>());

            var pubKey = (RsaKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Modulus, Is.EqualTo(new BigInteger(n)));

            var getPassphrase = default(SshPrivateKey.GetPassphraseFunc);

            if (encryption != "none")
            {
                var pw = ReadStringResourceFile("PuttyTestData", "pass");
                getPassphrase = () => Encoding.UTF8.GetBytes(pw);
            }

            var privParam = key.Decrypt(getPassphrase, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<RsaPrivateCrtKeyParameters>());
            Assert.That(comment, Is.EqualTo("rsa-key-20220505"));

            var privKey = (RsaPrivateCrtKeyParameters)privParam;

            Assert.That(privKey.Modulus, Is.EqualTo(new BigInteger(n)));
            Assert.That(privKey.P, Is.EqualTo(new BigInteger(p)));
            Assert.That(privKey.Q, Is.EqualTo(new BigInteger(q)));
        }

        [TestCase("v2", "none", null)]
        [TestCase("v2", "aes256cbc", null)]
        [TestCase("v3", "none", "none")]
        [TestCase("v3", "aes256cbc", "argon2i")]
        public void TestThatReadingDsaKeyWorks(
            string version,
            string encryption,
            string keyDerivation
        )
        {
            var y = ReadStringResourceFile("PuttyTestData", "dsa.param.y");
            var x = ReadStringResourceFile("PuttyTestData", "dsa.param.x");

            var kdf = keyDerivation == null ? string.Empty : $"-{keyDerivation}";
            var file = OpenResourceFile("PuttyTestData", $"dsa-{version}-{encryption}{kdf}.ppk");
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

            var pubKey = (DsaPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.Y, Is.EqualTo(new BigInteger(y)));

            var getPassphrase = default(SshPrivateKey.GetPassphraseFunc);

            if (encryption != "none")
            {
                var pw = ReadStringResourceFile("PuttyTestData", "pass");
                getPassphrase = () => Encoding.UTF8.GetBytes(pw);
            }

            var privParam = key.Decrypt(getPassphrase, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<DsaPrivateKeyParameters>());
            Assert.That(comment, Is.EqualTo("dsa-key-20220506"));

            var privKey = (DsaPrivateKeyParameters)privParam;

            Assert.That(privKey.X, Is.EqualTo(new BigInteger(x)));
        }

        [TestCase("nistp256", "v2", "none", null)]
        [TestCase("nistp256", "v2", "aes256cbc", null)]
        [TestCase("nistp256", "v3", "none", "none")]
        [TestCase("nistp256", "v3", "aes256cbc", "argon2d")]
        [TestCase("nistp384", "v2", "none", null)]
        [TestCase("nistp384", "v2", "aes256cbc", null)]
        [TestCase("nistp384", "v3", "none", "none")]
        [TestCase("nistp384", "v3", "aes256cbc", "argon2d")]
        [TestCase("nistp521", "v2", "none", null)]
        [TestCase("nistp521", "v2", "aes256cbc", null)]
        [TestCase("nistp521", "v3", "none", "none")]
        [TestCase("nistp521", "v3", "aes256cbc", "argon2d")]
        public void TestThatReadingEcdsaKeyWorks(
            string curve,
            string version,
            string encryption,
            string keyDerivation
        )
        {
            var curveName = ReadStringResourceFile("PuttyTestData", $"ecdsa-{curve}.param.curve");
            var q = ReadStringResourceFile("PuttyTestData", $"ecdsa-{curve}.param.q");
            var d = ReadStringResourceFile("PuttyTestData", $"ecdsa-{curve}.param.d");

            var kdf = keyDerivation == null ? string.Empty : $"-{keyDerivation}";
            var file = OpenResourceFile(
                "PuttyTestData",
                $"ecdsa-{curve}-{version}-{encryption}{kdf}.ppk"
            );
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<ECPublicKeyParameters>());

            var pubKey = (ECPublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(
                pubKey.Q,
                Is.EqualTo(NistNamedCurves.GetByName(curveName).Curve.DecodePoint(Util.FromHex(q)))
            );

            var getPassphrase = default(SshPrivateKey.GetPassphraseFunc);

            if (encryption != "none")
            {
                var pw = ReadStringResourceFile("PuttyTestData", "pass");
                getPassphrase = () => Encoding.UTF8.GetBytes(pw);
            }

            var privParam = key.Decrypt(getPassphrase, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<ECPrivateKeyParameters>());
            Assert.That(comment, Is.EqualTo("ecdsa-key-20220506"));

            var privKey = (ECPrivateKeyParameters)privParam;

            Assert.That(privKey.D, Is.EqualTo(new BigInteger(d)));
        }

        [TestCase("v2", "none", null)]
        [TestCase("v2", "aes256cbc", null)]
        [TestCase("v3", "none", "none")]
        [TestCase("v3", "aes256cbc", "argon2id")]
        public void TestThatReadingEd25519KeyWorks(
            string version,
            string encryption,
            string keyDerivation
        )
        {
            var pub = ReadStringResourceFile("PuttyTestData", $"eddsa-ed25519.param.pub");
            var priv = ReadStringResourceFile("PuttyTestData", $"eddsa-ed25519.param.priv");

            var kdf = keyDerivation == null ? string.Empty : $"-{keyDerivation}";
            var file = OpenResourceFile(
                "PuttyTestData",
                $"eddsa-ed25519-{version}-{encryption}{kdf}.ppk"
            );
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

            var pubKey = (Ed25519PublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.GetEncoded(), Is.EqualTo(Util.FromHex(pub)));

            var getPassphrase = default(SshPrivateKey.GetPassphraseFunc);

            if (encryption != "none")
            {
                var pw = ReadStringResourceFile("PuttyTestData", "pass");
                getPassphrase = () => Encoding.UTF8.GetBytes(pw);
            }

            var privParam = key.Decrypt(getPassphrase, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<Ed25519PrivateKeyParameters>());
            Assert.That(comment, Is.EqualTo("eddsa-key-20220506"));

            var privKey = (Ed25519PrivateKeyParameters)privParam;
            Assert.That(privKey.GetEncoded(), Is.EqualTo(Util.FromHex(priv)));
            Assert.That(privKey.GeneratePublicKey(), Is.EqualTo(pubKey));
        }

        [TestCase("v2", "none", null)]
        [TestCase("v2", "aes256cbc", null)]
        [TestCase("v3", "none", "none")]
        [TestCase("v3", "aes256cbc", "argon2id")]
        public void TestThatReadingEd448KeyWorks(
            string version,
            string encryption,
            string keyDerivation
        )
        {
            var pub = ReadStringResourceFile("PuttyTestData", $"eddsa-ed448.param.pub");
            var priv = ReadStringResourceFile("PuttyTestData", $"eddsa-ed448.param.priv");

            var kdf = keyDerivation == null ? string.Empty : $"-{keyDerivation}";
            var file = OpenResourceFile(
                "PuttyTestData",
                $"eddsa-ed448-{version}-{encryption}{kdf}.ppk"
            );
            var key = SshPrivateKey.Read(file);

            Assert.That(() => file.ReadByte(), Throws.TypeOf<ObjectDisposedException>());

            Assert.That(key.PublicKey.Parameter.IsPrivate, Is.False);
            Assert.That(key.PublicKey.Parameter, Is.TypeOf<Ed448PublicKeyParameters>());

            var pubKey = (Ed448PublicKeyParameters)key.PublicKey.Parameter;
            Assert.That(pubKey.GetEncoded(), Is.EqualTo(Util.FromHex(pub)));

            var getPassphrase = default(SshPrivateKey.GetPassphraseFunc);

            if (encryption != "none")
            {
                var pw = ReadStringResourceFile("PuttyTestData", "pass");
                getPassphrase = () => Encoding.UTF8.GetBytes(pw);
            }

            var privParam = key.Decrypt(getPassphrase, null, out var comment);

            Assert.That(privParam.IsPrivate);
            Assert.That(privParam, Is.TypeOf<Ed448PrivateKeyParameters>());
            Assert.That(comment, Is.EqualTo("eddsa-key-20220506"));

            var privKey = (Ed448PrivateKeyParameters)privParam;
            Assert.That(privKey.GetEncoded(), Is.EqualTo(Util.FromHex(priv)));
            Assert.That(privKey.GeneratePublicKey(), Is.EqualTo(pubKey));
        }

        [Test]
        public void TestThatNonAsciiPassphraseWorks()
        {
            var pw = ReadStringResourceFile("RegressionTestData", "japanese-passphrase.txt");
            byte[] getPassphrase() => Encoding.UTF8.GetBytes(pw);

            var file = OpenResourceFile(
                "RegressionTestData",
                "putty-private-key-with-japanese-passphrase.ppk"
            );
            var key = SshPrivateKey.Read(file);

            Assert.DoesNotThrow(() => key.Decrypt(getPassphrase, null, out var comment));
        }
    }
}
