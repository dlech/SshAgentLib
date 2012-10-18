using dlech.PageantSharp;
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using NUnit.Framework;
using PageantSharpNUnitTest.Properties;
using System.IO;
using System.Text;

namespace PageantSharpTest
{

  /// <summary>
  ///This is a test class for Agent class and is intended
  ///to contain all Agent Unit Tests
  ///</summary>
  [TestFixture()]
  public class AgentTest
  {
    private const string cAgentFailure = "AAAAAQU=";
    private const string cAgentSucess = "AAAAAQV=";

    private Agent mAgent;
    private PpkKey mSsh2RsaKey;
    private List<PpkKey> mSsh2KeyList;

    [TestFixtureSetUp()]
    public void Setup()
    {
      mSsh2RsaKey = PpkFile.ParseData(Resources.ssh2_rsa_no_passphrase_ppk,
                                      null, WarnOldFileFormat);
      mSsh2KeyList = new List<PpkKey>();
      mSsh2KeyList.Add(mSsh2RsaKey);

      mAgent = new TestAgent(GetSsh2KeyList, GetSsh2Key, AddSsh2Key);
    }

    private class TestAgent : Agent
    {
      public TestAgent(GetSSH2KeyListCallback aGetSSH2KeyListCallback,
                       GetSSH2KeyCallback aGetSSH2KeyCallback,
                       AddSSH2KeyCallback aAddSSH2KeyCallback) :
        base(aGetSSH2KeyListCallback, aGetSSH2KeyCallback, aAddSSH2KeyCallback) { }
    }
    
    private PpkKey GetSsh2Key(byte[] fingerprint)
    {
      return mSsh2RsaKey;
    }

    private List<PpkKey> GetSsh2KeyList()
    {
      return mSsh2KeyList;
    }

    private bool AddSsh2Key(PpkKey key)
    {
      return true;
    }

    private void WarnOldFileFormat()
    {
      // do nothing
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REQUEST_IDENTITIES()
    {
      string expected = "AAAAzAwAAAABAAAAlQAAAAdzc2gtcnNhAAAAASUAAACBAIVqnRL" +
        "P5c9a+C/GQAEu+q1+4Y966yP+hTZQcOhEW2tlRZp9gB8UMGZhx5qjPlLYmOe2p4Iw/X" +
        "0208y++AtPn/za0WPgWF39XBfruV5ozSsoK7CKt8jzGVeKvGHDf5bPQjnMpzkDCBJiR" +
        "ekNCw+xrfVL+co6nNgMu1VYRqmTZyHhAAAAKlBhZ2VhbnRTaGFycCB0ZXN0OiBTU0gy" +
        "LVJTQSwgbm8gcGFzc3BocmFzZQ==";

      byte[] buffer = new byte[4096];
      Array.Copy(new byte[] { 0, 0, 0, 1, 11 }, buffer, 5);
      MemoryStream stream = new MemoryStream(buffer);
      mAgent.AnswerMessage(stream);
      byte[] response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      string actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(expected, actual);
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY()
    {
      byte[] buffer = new byte[4096];
      Array.Copy(new byte[] { 0, 0, 0, 1, 17 }, buffer, 5);
      MemoryStream stream = new MemoryStream(buffer);
      mAgent.AnswerMessage(stream);
      byte[] response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      string actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentSucess, actual);
    }

    [Test()]
    public void TestDsaSig()
    {
      DSA dsa1 = DSA.Create();
      DSAParameters dsa1params = dsa1.ExportParameters(true);

      DsaParameters dsa2common = new DsaParameters(
          new BigInteger(1, dsa1params.P),
          new BigInteger(1, dsa1params.Q),
          new BigInteger(1, dsa1params.G));
      DsaPublicKeyParameters dsa2public = new DsaPublicKeyParameters(
          new BigInteger(1, dsa1params.Y), dsa2common);
      DsaPrivateKeyParameters dsa2private = new DsaPrivateKeyParameters(
          new BigInteger(1, dsa1params.X), dsa2common);

      byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

      SHA1 sha = SHA1.Create();
      sha.ComputeHash(data);
      byte[] dsa1result = dsa1.CreateSignature(sha.Hash);

      ISigner dsa2signer = SignerUtilities.GetSigner("SHA-1withDSA");
      //algName = PpkFile.PublicKeyAlgorithms.ssh_dss;

      dsa2signer.Init(true, dsa2private);
      dsa2signer.BlockUpdate(data, 0, data.Length);
      byte[] dsa2result = dsa2signer.GenerateSignature();

      Assert.IsTrue(dsa1.VerifySignature(sha.Hash, dsa2result));

      dsa2signer.Init(false, dsa2public);
      dsa2signer.BlockUpdate(data, 0, data.Length);

      Assert.IsTrue(dsa2signer.VerifySignature(dsa1result));

    }
  }
}
