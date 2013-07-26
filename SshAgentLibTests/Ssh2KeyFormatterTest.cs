//
// Ssh2KeyFormatterTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013 David Lechner
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
  ///This is a test class for Ssh2KeyFormatter and is intended
  ///to contain all Ssh2KeyFormatter Unit Tests
  ///</summary>
  [TestFixture()]
  public class Ssh2KeyFormatterTest
  {

    private Ssh2KeyFormatter.GetPassphraseCallback mPassphraseCallback;

    [TestFixtureSetUp()]
    public void SetupFixture()
    {
      mPassphraseCallback = delegate(string comment)
      {
        SecureString passphrase = new SecureString();
        foreach (char c in "passphrase") {
          passphrase.AppendChar(c);
        }
        return passphrase;
      };
    }

    [Test()]
    public void TestDeserialize()
    {
      Ssh2KeyFormatter formatter;
      ISshKey key;
      byte[] buffer = new byte[4096];
      MemoryStream memStream = new MemoryStream(buffer);
      int i;

      formatter = new Ssh2KeyFormatter();
      key = formatter.Deserialize(Resources.rsa_no_passphrase);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));
      formatter.Serialize(memStream, key.GetPrivateKeyParameters());
      for (i = 0; i < Resources.rsa_no_passphrase.Length; i++) {
        // TODO ignore line endings
        //Assert.That(buffer[i], Is.EqualTo(Resources.rsa_no_passphrase[i]));
      }

        formatter.GetPassphraseCallbackMethod = mPassphraseCallback;
      key = formatter.Deserialize(Resources.rsa_with_passphrase);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));

      formatter = new Ssh2KeyFormatter();
      key = formatter.Deserialize(Resources.dsa_no_passphrase);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS));

      formatter.GetPassphraseCallbackMethod = mPassphraseCallback;
      key = formatter.Deserialize(Resources.dsa_with_passphrase);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS));

      formatter = new Ssh2KeyFormatter();
      key = formatter.Deserialize(Resources.ecdsa_no_passphrase);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP256));

      formatter.GetPassphraseCallbackMethod = mPassphraseCallback;
      key = formatter.Deserialize(Resources.ecdsa_with_passphrase);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.ECDSA_SHA2_NISTP256));

    }
    
  }
}

