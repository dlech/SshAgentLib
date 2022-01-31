// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using dlech.SshAgentLib;

using NUnit.Framework;
using SshAgentLib.Keys;
using Org.BouncyCastle.Crypto.Parameters;

using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.Keys
{
    [TestFixture]
    public sealed class Rfc4716PublicKeyReaderTests
    {
        [Test]
        public void TestThatReadingRfc4716Example1Works()
        {
            using (var file = OpenResourceFile("Rfc4716PublicKey", "example1"))
            {
                var key = Rfc4716PublicKey.Read(file);

                Assert.That(key.Version, Is.EqualTo(SshVersion.SSH2));
                Assert.That(key.Parameter, Is.TypeOf<RsaKeyParameters>());
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
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());
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
                Assert.That(key.Parameter, Is.TypeOf<DsaPublicKeyParameters>());
                Assert.That(key.Comment, Is.EqualTo("DSA Public Key for use with MyIsp"));
            }
        }
    }
}
