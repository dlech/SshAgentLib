// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using dlech.SshAgentLib;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using SshAgentLib.Keys;

using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.Keys
{
    [TestFixture]
    public sealed class Rfc4716PublicKeyReaderTests
    {
        // example data from https://datatracker.ietf.org/doc/html/rfc4716

        [Test]
        public void TestThatReadingRfc4716Example1Works()
        {
            using (var file = OpenResourceFile("Rfc4716PublicKey", "example1"))
            {
                var key = Rfc4716PublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<RsaKeyParameters>());
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo("SHA256:csG+ujEVjJLZpYPqLUDdw20LVTQMjD4FWsNmsr1etGE")
                );
                Assert.That(
                    key.Comment,
                    Is.EqualTo("1024-bit RSA, converted from OpenSSH by me@example.com")
                );
            }
        }

        [Test]
        public void TestThatReadingRfc4716Example2Works()
        {
            using (var file = OpenResourceFile("Rfc4716PublicKey", "example2"))
            {
                var key = Rfc4716PublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo("SHA256:UPFxqc1qGwD5OpK2pgb6Y1YxpiMS+XZeSbYhgyw6LiE")
                );
                Assert.That(
                    key.Comment,
                    Is.EqualTo("This is my public key for use on servers which I don't like.")
                );
            }
        }

        [Test]
        public void TestThatReadingRfc4716Example3Works()
        {
            using (var file = OpenResourceFile("Rfc4716PublicKey", "example3"))
            {
                var key = Rfc4716PublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo("SHA256:UPFxqc1qGwD5OpK2pgb6Y1YxpiMS+XZeSbYhgyw6LiE")
                );
                Assert.That(key.Comment, Is.EqualTo("DSA Public Key for use with MyIsp"));
            }
        }

        [Test]
        public void TestThatReadingRfc4716Example4Works()
        {
            using (var file = OpenResourceFile("Rfc4716PublicKey", "example4"))
            {
                var key = Rfc4716PublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter.IsPrivate, Is.False);
                Assert.That(key.Parameter, Is.TypeOf<RsaKeyParameters>());
                Assert.That(
                    key.Sha256Hash,
                    Is.EqualTo("SHA256:MQHWhS9nhzUezUdD42ytxubZoBKrZLbyBZzxCkmnxXc")
                );
                Assert.That(
                    key.Comment,
                    Is.EqualTo("1024-bit rsa, created by me@example.com Mon Jan 15 08:31:24 2001")
                );
            }
        }

        [Test]
        public void TestThatCommentWithColonWorks()
        {
            using (
                var file = OpenResourceFile(
                    "RegressionTestData",
                    "rfc4716-public-key-with-colon-in-comment"
                )
            )
            {
                var key = Rfc4716PublicKey.Read(file);
                Assert.That(key.Comment, Is.EqualTo("PageantSharp test: SSH2-RSA, no passphrase"));
            }
        }
    }
}
