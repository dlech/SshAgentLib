//
// Ssh1KeyFormatterTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013,2015,2022 David Lechner
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

using System.Security;
using dlech.SshAgentLib;
using SshAgentLibTests.Properties;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    ///This is a test class for Ssh1KeyFormatter and is intended
    ///to contain all Ssh1KeyFormatter Unit Tests
    ///</summary>
    ///<remarks>
    ///Tests based on /src/regress/usr.bin/ssh/untistests/sshkey/test_file.c
    ///from OpenBSD source code.
    /// </remarks>
    [TestFixture]
    public class Ssh1KeyFormatterTest
    {
        private Ssh1KeyFormatter.GetPassphraseCallback passphraseCallback;

        public Ssh1KeyFormatterTest()
        {
            passphraseCallback = delegate(string comment)
            {
                SecureString passphrase = new SecureString();
                foreach (var c in Resources.pw.Trim())
                {
                    passphrase.AppendChar(c);
                }
                return passphrase;
            };
        }

        [Test]
        public void TestDeserializeRsaFromPrivate()
        {
            var formatter = new Ssh1KeyFormatter();
            var key = formatter.Deserialize(Resources.rsa1_1);
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH1));
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshRsa));
            var publicKey = (RsaKeyParameters)key.GetPublicKeyParameters();
            var expected = new BigInteger(Resources.rsa1_1_param_n.Trim(), 16);
            Assert.That(publicKey.Modulus, Is.EqualTo(expected));
        }

        [Test]
        public void TestDeserializeRsaFromPrivateWithPassphrase()
        {
            var formatter = new Ssh1KeyFormatter();
            formatter.GetPassphraseCallbackMethod = passphraseCallback;
            var key = formatter.Deserialize(Resources.rsa1_1_pw);
            Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SshRsa));
            Assert.That(key.Version, Is.EqualTo(SshVersion.SSH1));
            var publicKey = (RsaKeyParameters)key.GetPublicKeyParameters();
            var expected = new BigInteger(Resources.rsa1_1_param_n.Trim(), 16);
            Assert.That(publicKey.Modulus, Is.EqualTo(expected));
        }
    }
}
