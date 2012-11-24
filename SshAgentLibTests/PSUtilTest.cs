using dlech.SshAgentLib;
using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{
    
  /// <summary>
  ///This is a test class for PSUtilTest and is intended
  ///to contain all PSUtilTest Unit Tests
  ///</summary>
  [TestFixture()]
  public class PSUtilTest
  {

    /// <summary>
    ///A test for TrimLeadingZero
    ///</summary>
    [Test()]
    public void TrimLeadingZeroTest()
    {
      PinnedByteArray array1 = new PinnedByteArray(new byte[] { 1, 2, 3, 4 });
      PSUtil.TrimLeadingZero(array1);
      Assert.That(array1.Data, Is.EqualTo(new byte[]{ 1, 2, 3, 4 }));

      PinnedByteArray array2 = new PinnedByteArray(new byte[] { 0, 1, 2, 3, 4 });
      PSUtil.TrimLeadingZero(array2);
      Assert.That(array2.Data, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
    }

    /// <summary>
    ///A test for ModMinusOne
    ///</summary>
    [Test()]
    public void ModMinusOneTest()
    {
      RSAParameters p;
      using (RSA rsa = RSA.Create()) {
        p = rsa.ExportParameters(true);
      }
      PinnedByteArray a = new PinnedByteArray(p.D);
      PinnedByteArray b = new PinnedByteArray(p.P);
      byte[] expected = p.DP;
     
      PinnedByteArray actual;
      actual = PSUtil.ModMinusOne(a, b);
      Assert.That(actual.Data, Is.EqualTo(expected));
    }
  }
}
