using System;
using NUnit.Framework;
using System.Reflection;
using System.IO;
using dlech.SshAgentLib;
using System.Security;
using System.Text;
using System.Resources;
using dlech.SshAgentLibTests.Properties;
using Org.BouncyCastle.Crypto;

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

