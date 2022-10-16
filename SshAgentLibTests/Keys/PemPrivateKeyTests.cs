// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System.IO;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SshAgentLib.Keys;
using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.Keys
{
    [TestFixture]
    public class PemPrivateKeyTests
    {
        [TestCase("rsa_1", false)]
        [TestCase("rsa_1", true)]
        [TestCase("rsa_2", false)]
        public void TestThatReadingRsaKeyWorks(string baseName, bool isEncrypted)
        {
            var n = ReadStringResourceFile("OpenSshTestData", $"{baseName}.param.n");
            var p = ReadStringResourceFile("OpenSshTestData", $"{baseName}.param.p");
            var q = ReadStringResourceFile("OpenSshTestData", $"{baseName}.param.q");
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var suffix = isEncrypted ? "_pw" : "";
            var file = OpenResourceFile("OpenSshTestData", $"{baseName}{suffix}");
            var key = SshPrivateKey.Read(file);

            Assert.That(key.IsEncrypted, Is.EqualTo(isEncrypted));
            Assert.That(key.HasKdf, Is.False);
            Assert.That(key.PublicKey, Is.Null);

            var getPassphrase = isEncrypted
                ? () => Encoding.UTF8.GetBytes(pw)
                : default(SshPrivateKey.GetPassphraseFunc);

            // decrypt multiple times to check for state corruption
            for (int i = 0; i < 2; i++)
            {
                var privParam = key.Decrypt(getPassphrase);
                Assert.That(privParam, Is.TypeOf<RsaPrivateCrtKeyParameters>());

                var rsa = (RsaPrivateCrtKeyParameters)privParam;
                Assert.That(rsa.Modulus, Is.EqualTo(new BigInteger(n, 16)));
                Assert.That(rsa.P, Is.EqualTo(new BigInteger(p, 16)));
                Assert.That(rsa.Q, Is.EqualTo(new BigInteger(q, 16)));
            }
        }

        [TestCase("dsa_1", false)]
        [TestCase("dsa_1", true)]
        public void TestThatReadingDsaKeyWorks(string baseName, bool isEncrypted)
        {
            var priv = ReadStringResourceFile("OpenSshTestData", $"{baseName}.param.priv");
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var suffix = isEncrypted ? "_pw" : "";
            var file = OpenResourceFile("OpenSshTestData", $"{baseName}{suffix}");
            var key = SshPrivateKey.Read(file);

            Assert.That(key.IsEncrypted, Is.EqualTo(isEncrypted));
            Assert.That(key.HasKdf, Is.False);
            Assert.That(key.PublicKey, Is.Null);

            var getPassphrase = isEncrypted
                ? () => Encoding.UTF8.GetBytes(pw)
                : default(SshPrivateKey.GetPassphraseFunc);

            // decrypt multiple times to check for state corruption
            for (int i = 0; i < 2; i++)
            {
                var privParam = key.Decrypt(getPassphrase);
                Assert.That(privParam, Is.TypeOf<DsaPrivateKeyParameters>());

                var dsa = (DsaPrivateKeyParameters)privParam;
                Assert.That(dsa.X, Is.EqualTo(new BigInteger(priv, 16)));
            }
        }

        [TestCase("ecdsa_1", false)]
        [TestCase("ecdsa_1", true)]
        [TestCase("ecdsa_2", false)]
        public void TestThatReadingEcdsaKeyWorks(string baseName, bool isEncrypted)
        {
            var priv = ReadStringResourceFile("OpenSshTestData", $"{baseName}.param.priv");
            var pw = ReadStringResourceFile("OpenSshTestData", "pw");

            var suffix = isEncrypted ? "_pw" : "";
            var file = OpenResourceFile("OpenSshTestData", $"{baseName}{suffix}");
            var key = SshPrivateKey.Read(file);

            Assert.That(key.IsEncrypted, Is.EqualTo(isEncrypted));
            Assert.That(key.HasKdf, Is.False);
            Assert.That(key.PublicKey, Is.Null);

            var getPassphrase = isEncrypted
                ? () => Encoding.UTF8.GetBytes(pw)
                : default(SshPrivateKey.GetPassphraseFunc);

            // decrypt multiple times to check for state corruption
            for (int i = 0; i < 2; i++)
            {
                var privParam = key.Decrypt(getPassphrase);
                Assert.That(privParam, Is.TypeOf<ECPrivateKeyParameters>());

                var ecdsa = (ECPrivateKeyParameters)privParam;
                Assert.That(ecdsa.D, Is.EqualTo(new BigInteger(priv, 16)));
            }
        }

        [TestCase("rsa_1")]
        [TestCase("dsa_1")]
        [TestCase("ecdsa_1")]
        public void TestThatGeneratingPublicKeyFileWorks(string baseName)
        {
            var publicKeyFile = ReadStringResourceFile("OpenSshTestData", $"{baseName}.pub");
            var publicKey = SshPublicKey.Read(
                new MemoryStream(Encoding.UTF8.GetBytes(publicKeyFile))
            );

            var file = OpenResourceFile("OpenSshTestData", $"{baseName}");

            var outStream = new MemoryStream();
            SshPrivateKey.CreatePublicKeyFromPrivateKey(file, outStream, null, publicKey.Comment);

            var generatedPublicKey = Encoding.UTF8.GetString(outStream.ToArray());
            Assert.That(generatedPublicKey, Is.EqualTo(publicKeyFile));
        }
    }
}
