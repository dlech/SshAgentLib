//
// Ssh1KeyFormatterTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
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
  ///This is a test class for Ssh1KeyFormatter and is intended
  ///to contain all Ssh1KeyFormatter Unit Tests
  ///</summary>
  [TestFixture()]
  public class Ssh1KeyFormatterTest
  {
    private const string cTestNotImplemented = "Test not implemented";

    private Ssh1KeyFormatter.GetPassphraseCallback mPassphraseCallback;

    [TestFixtureSetUp()]
    public void SetupFixture()
    {
      mPassphraseCallback = delegate(string comment)
      {
        SecureString passphrase = new SecureString();
        foreach (char c in "PageantSharp") {
          passphrase.AppendChar(c);
        }
        return passphrase;
      };
    }

    [Test()]
    public void TestDeserialize()
    {
      Ssh1KeyFormatter formatter;
      ISshKey key;
      byte[] buffer = new byte[4096];
      MemoryStream memStream = new MemoryStream(buffer);
      int i;

      formatter = new Ssh1KeyFormatter();
      key = formatter.Deserialize(Resources.ssh1_rsa_no_passphrase_ppk);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));
      Assert.That(key.Version, Is.EqualTo(SshVersion.SSH1));
      formatter.Serialize(memStream, key);
      for (i = 0; i < Resources.ssh1_rsa_no_passphrase_ppk.Length; i++)
      {
        // TODO ignore line endings
        //Assert.That(buffer[i], Is.EqualTo(Resources.rsa_no_passphrase[i]));
      }

      formatter.GetPassphraseCallbackMethod = mPassphraseCallback;
      key = formatter.Deserialize(Resources.ssh1_rsa_ppk);
      Assert.That(key.Algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA));
      Assert.That(key.Version, Is.EqualTo(SshVersion.SSH1));
    }
  }
}

