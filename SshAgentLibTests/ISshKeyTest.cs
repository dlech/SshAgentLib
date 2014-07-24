using System;
using System.Linq;

using dlech.SshAgentLib;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

using NUnit.Framework;

namespace dlech.SshAgentLibTests
{
  [TestFixture()]
  public class ISshKeyTest
  {
    [Test()]
    public void TestFormatSignature()
    {
      var random = new Random();
      var dsa_key = new SshKey(SshVersion.SSH2, new DsaPublicKeyParameters (
        new BigInteger ("1"),
        new DsaParameters(new BigInteger ("2"), new BigInteger ("3"),
                          new BigInteger ("4"))));
      // test that dsa signature works when values are not full 20 bytes.
      byte[] r_bytes = new byte[19];
      byte[] s_bytes = new byte[19];
      random.NextBytes(r_bytes);
      random.NextBytes(s_bytes);
      var r = new DerInteger(r_bytes);
      var s = new DerInteger(s_bytes);
      var sequence = new DerSequence(r, s);
      var signature = dsa_key.FormatSignature(sequence.GetEncoded());
      Assert.That(signature.Count(), Is.EqualTo(40));
    }
  }
}

