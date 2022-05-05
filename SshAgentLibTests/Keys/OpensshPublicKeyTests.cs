// SPDX-License-Identifier: MIT
// Copyright (c) 2015,2022 David Lechner <david@lechnology.com>

// Run tests on keys from OpenSSH source code tests.
// Expected hashes come from `ssh-keygen -l -f <file>`.

using dlech.SshAgentLib;
using dlech.SshAgentLib.Crypto;
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
        [Test]
        public void TestThatReadingRsaPublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "rsa_1.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<RsaKeyParameters>());

                var rsa = (RsaKeyParameters)key.Parameter;
                var n = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.n");

                Assert.That(rsa.Modulus, Is.EqualTo(new BigInteger(n, 16)));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "rsa_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("RSA test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "rsa_1.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingRsaPublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "rsa_1-cert.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<RsaKeyParameters>());

                var rsa = (RsaKeyParameters)key.Parameter;
                var n = ReadStringResourceFile("OpenSshTestData", "rsa_1.param.n");

                Assert.That(rsa.Modulus, Is.EqualTo(new BigInteger(n, 16)));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "rsa_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("RSA test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "rsa_1-cert.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingDsaPublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "dsa_1.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

                var dsa = (DsaPublicKeyParameters)key.Parameter;
                var g = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.g");
                var pub = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.pub");

                Assert.That(dsa.Parameters.G, Is.EqualTo(new BigInteger(g, 16)));
                Assert.That(dsa.Y, Is.EqualTo(new BigInteger(pub, 16)));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "dsa_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("DSA test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "dsa_1.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingDsaPublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "dsa_1-cert.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());

                var dsa = (DsaPublicKeyParameters)key.Parameter;
                var g = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.g");
                var pub = ReadStringResourceFile("OpenSshTestData", "dsa_1.param.pub");

                Assert.That(dsa.Parameters.G, Is.EqualTo(new BigInteger(g, 16)));
                Assert.That(dsa.Y, Is.EqualTo(new BigInteger(pub, 16)));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "dsa_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("DSA test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "dsa_1-cert.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingEcdsaPublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ecdsa_1.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<ECPublicKeyParameters>());

                var ec = (ECPublicKeyParameters)key.Parameter;
                var curve = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.curve");
                var pub = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.pub");

                Assert.That(
                    ec.Parameters.Curve,
                    Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
                );
                Assert.That(ec.Q, Is.EqualTo(ec.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ECDSA test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_1.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingEcdsaPublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ecdsa_1-cert.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<ECPublicKeyParameters>());

                var ec = (ECPublicKeyParameters)key.Parameter;
                var curve = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.curve");
                var pub = ReadStringResourceFile("OpenSshTestData", "ecdsa_1.param.pub");

                Assert.That(
                    ec.Parameters.Curve,
                    Is.EqualTo(X962NamedCurves.GetByName(curve).Curve)
                );
                Assert.That(ec.Q, Is.EqualTo(ec.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ECDSA test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_1-cert.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingEcdsaPublicKeyWorks2()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ecdsa_2.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<ECPublicKeyParameters>());

                var ec = (ECPublicKeyParameters)key.Parameter;
                var curve = ReadStringResourceFile("OpenSshTestData", "ecdsa_2.param.curve");
                var pub = ReadStringResourceFile("OpenSshTestData", "ecdsa_2.param.pub");

                Assert.That(ec.Parameters.Curve, Is.EqualTo(SecNamedCurves.GetByName(curve).Curve));
                Assert.That(ec.Q, Is.EqualTo(ec.Parameters.Curve.DecodePoint(Hex.Decode(pub))));

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_2.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ECDSA test key #2"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_2.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingEd25519PublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ed25519_1.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<Ed25519PublicKeyParameter>());

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_1.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingEd25519PublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ed25519_1-cert.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<Ed25519PublicKeyParameter>());

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_1-cert.pub"))
                );
            }
        }

        [Test]
        public void TestThatReadingEd25519PublicKeyWorks2()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ed25519_2.pub"))
            {
                var key = SshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<Ed25519PublicKeyParameter>());

                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_2.fp"))
                );
                // Upstream bug - comment says #1 instead of #1 in the source file
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
                Assert.That(
                    key.AuthorizedKeysString,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_2.pub"))
                );
            }
        }
    }
}
