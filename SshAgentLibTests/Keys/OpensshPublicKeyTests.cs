// SPDX-License-Identifier: MIT
// Copyright (c) 2015,2022 David Lechner <david@lechnology.com>

// Run tests on keys from OpenSSH source code tests.
// Expected hashes come from `ssh-keygen -l -f <file>`.

using dlech.SshAgentLib;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using SshAgentLib.Keys;
using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.Keys
{
    [TestFixture]
    public class OpensshPublicKeyTests
    {
        [TestCase("rsa_1", false)]
        [TestCase("rsa_1", true)]
        [TestCase("rsa_2", false)]
        public void TestThatReadingRsaPublicKeyWorks(string keyName, bool withCert)
        {
            var fileBase = $"{keyName}{(withCert ? "-cert" : "")}";
            var fileNumber = keyName.Substring(keyName.Length - 1, 1);

            using (var file = OpenResourceFile("OpenSshTestData", $"{fileBase}.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<RsaKeyParameters>());

                var rsa = (RsaKeyParameters)key.Parameter;
                var n = ReadStringResourceFile("OpenSshTestData", $"{keyName}.param.n");

                Assert.That(rsa.Modulus, Is.EqualTo(new BigInteger(n, 16)));

                Assert.That(
                    key.Sha256Fingerprint,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo($"RSA test key #{fileNumber}"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.pub"))
                );

                if (withCert)
                {
                    Assert.That(key.Nonce, Is.Not.Null);
                    Assert.That(key.Certificate, Is.Not.Null);
                }
                else
                {
                    Assert.That(key.Nonce, Is.Null);
                    Assert.That(key.Certificate, Is.Null);
                }
            }
        }

        [TestCase("dsa_1", false)]
        [TestCase("dsa_1", true)]
        [TestCase("dsa_2", false)]
        public void TestThatReadingDsaPublicKeyWorks(string keyName, bool withCert)
        {
            var fileBase = $"{keyName}{(withCert ? "-cert" : "")}";
            var fileNumber = keyName.Substring(keyName.Length - 1, 1);

            using (var file = OpenResourceFile("OpenSshTestData", $"{fileBase}.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

                if (keyName != "dsa_2")
                {
                    var dsa = (DsaPublicKeyParameters)key.Parameter;
                    var g = ReadStringResourceFile("OpenSshTestData", $"{keyName}.param.g");
                    var pub = ReadStringResourceFile("OpenSshTestData", $"{keyName}.param.pub");

                    Assert.That(dsa.Parameters.G, Is.EqualTo(new BigInteger(g, 16)));
                    Assert.That(dsa.Y, Is.EqualTo(new BigInteger(pub, 16)));
                }

                Assert.That(
                    key.Sha256Fingerprint,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo($"DSA test key #{fileNumber}"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.pub"))
                );

                if (withCert)
                {
                    Assert.That(key.Nonce, Is.Not.Null);
                    Assert.That(key.Certificate, Is.Not.Null);
                }
                else
                {
                    Assert.That(key.Nonce, Is.Null);
                    Assert.That(key.Certificate, Is.Null);
                }
            }
        }

        [TestCase("ecdsa_1", false)]
        [TestCase("ecdsa_1", true)]
        [TestCase("ecdsa_2", false)]
        public void TestThatReadingEcdsaPublicKeyWorks(string keyName, bool withCert)
        {
            var fileBase = $"{keyName}{(withCert ? "-cert" : "")}";
            var fileNumber = keyName.Substring(keyName.Length - 1, 1);

            using (var file = OpenResourceFile("OpenSshTestData", $"{fileBase}.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<ECPublicKeyParameters>());

                var ec = (ECPublicKeyParameters)key.Parameter;
                var curve = ReadStringResourceFile("OpenSshTestData", $"{keyName}.param.curve");
                var pub = ReadStringResourceFile("OpenSshTestData", $"{keyName}.param.pub");

                Assert.That(
                    ec.Parameters.Curve,
                    Is.EqualTo(
                        (X962NamedCurves.GetByName(curve) ?? SecNamedCurves.GetByName(curve)).Curve
                    )
                );
                Assert.That(ec.Q, Is.EqualTo(ec.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

                Assert.That(
                    key.Sha256Fingerprint,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo($"ECDSA test key #{fileNumber}"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.pub"))
                );

                if (withCert)
                {
                    Assert.That(key.Nonce, Is.Not.Null);
                    Assert.That(key.Certificate, Is.Not.Null);
                }
                else
                {
                    Assert.That(key.Nonce, Is.Null);
                    Assert.That(key.Certificate, Is.Null);
                }
            }
        }

        [TestCase("ed25519_1", false)]
        [TestCase("ed25519_1", true)]
        [TestCase("ed25519_2", false)]
        public void TestThatReadingEd25519PublicKeyWorks(string keyName, bool withCert)
        {
            var fileBase = $"{keyName}{(withCert ? "-cert" : "")}";

            using (var file = OpenResourceFile("OpenSshTestData", $"{fileBase}.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<Ed25519PublicKeyParameters>());

                Assert.That(
                    key.Sha256Fingerprint,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", $"{fileBase}.pub"))
                );

                if (withCert)
                {
                    Assert.That(key.Nonce, Is.Not.Null);
                    Assert.That(key.Certificate, Is.Not.Null);
                }
                else
                {
                    Assert.That(key.Nonce, Is.Null);
                    Assert.That(key.Certificate, Is.Null);
                }
            }
        }
    }
}
