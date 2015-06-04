//
// PemKeyFormatterTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2015 David Lechner
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

using System.IO;
using System.Security;
using dlech.SshAgentLib;
using dlech.SshAgentLibTests.Properties;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{

  /// <summary>
  ///This is a test class for PemKeyFormatter and is intended
  ///to contain all PemKeyFormatter Unit Tests
  ///</summary>
  [TestFixture()]
  public class PemKeyFormatterTest
  {

    private KeyFormatter.GetPassphraseCallback passphraseCallback;

    [TestFixtureSetUp()]
    public void SetupFixture()
    {
      passphraseCallback = delegate(string comment)
      {
        SecureString passphrase = new SecureString();
        foreach (char c in "passphrase") {
          passphrase.AppendChar(c);
        }
        return passphrase;
      };
    }

    [Test()]
    public void TestDeserialize_RSA()
    {
        TestDeserialize(Resources.rsa_no_passphrase, PublicKeyAlgorithm.SSH_RSA);
        TestDeserialize(Resources.rsa_with_passphrase, PublicKeyAlgorithm.SSH_RSA);
    }

    [Test()]
    public void TestDeserialize_DSA()
    {
        TestDeserialize(Resources.dsa_no_passphrase, PublicKeyAlgorithm.SSH_DSS);
        TestDeserialize(Resources.dsa_with_passphrase, PublicKeyAlgorithm.SSH_DSS);
    }

    [Test()]
    public void TestDeserialize_ECDSA()
    {
        TestDeserialize(Resources.ecdsa_no_passphrase, PublicKeyAlgorithm.ECDSA_SHA2_NISTP256);
        TestDeserialize(Resources.ecdsa_with_passphrase, PublicKeyAlgorithm.ECDSA_SHA2_NISTP256);
    }

    void TestDeserialize(byte[] data, PublicKeyAlgorithm alg)
    {
        var formatter = new PemKeyFormatter();
        formatter.GetPassphraseCallbackMethod = passphraseCallback;
        var key = formatter.Deserialize(data);
        Assert.That(key.Algorithm, Is.EqualTo(alg));
    }
  }
}
