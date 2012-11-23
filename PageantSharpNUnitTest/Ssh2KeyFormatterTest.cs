using System;
using NUnit.Framework;
using System.Reflection;
using System.IO;
using dlech.PageantSharp;
using System.Security;
using System.Text;
using System.Resources;
using PageantSharpTests.Properties;
using Org.BouncyCastle.Crypto;

namespace PageantSharpTest
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
      mPassphraseCallback = delegate()
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

