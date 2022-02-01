// SPDX-License-Identifier: MIT
// Copyright (c) 2015,2022 David Lechner <david@lechnology.com>

// Run tests on keys from OpenSSH source code tests.
// Expected hashes come from `ssh-keygen -l -f <file>`.

using dlech.SshAgentLib;
using NUnit.Framework;
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
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshRsa));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "rsa_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("RSA test key #1"));
            }
        }

        [Test]
        public void TestThatReadingRsaPublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "rsa_1-cert.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshRsaCertV1));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "rsa_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("RSA test key #1"));
            }
        }

        [Test]
        public void TestThatReadingDsaPublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "dsa_1.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshDss));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "dsa_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("DSA test key #1"));
            }
        }

        [Test]
        public void TestThatReadingDsaPublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "dsa_1-cert.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshDssCertV1));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "dsa_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("DSA test key #1"));
            }
        }

        [Test]
        public void TestThatReadingEcdsaPublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ecdsa_1.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.EcdsaSha2Nistp256));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ECDSA test key #1"));
            }
        }

        [Test]
        public void TestThatReadingEcdsaPublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ecdsa_1-cert.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ECDSA test key #1"));
            }
        }

        [Test]
        public void TestThatReadingEcdsaPublicKeyWorks2()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ecdsa_2.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.EcdsaSha2Nistp521));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ecdsa_2.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ECDSA test key #2"));
            }
        }

        [Test]
        public void TestThatReadingEd25519PublicKeyWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ed25519_1.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshEd25519));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_1.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
            }
        }

        [Test]
        public void TestThatReadingEd25519PublicKeyWithCertWorks()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ed25519_1-cert.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshEd25519CertV1));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_1-cert.fp"))
                );
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
            }
        }

        [Test]
        public void TestThatReadingEd25519PublicKeyWorks2()
        {
            using (var file = OpenResourceFile("OpenSshTestData", "ed25519_2.pub"))
            {
                var key = OpensshPublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshEd25519));
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo(ReadStringResourceFile("OpenSshTestData", "ed25519_2.fp"))
                );
                // Upstream bug - comment says #1 instead of #1 in the source file
                Assert.That(key.Comment, Is.EqualTo("ED25519 test key #1"));
            }
        }
    }
}
