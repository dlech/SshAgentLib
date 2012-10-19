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
    private const string cAgentSucess = "AAAAAQY=";

    private Agent mAgent;
    private PpkKey mSsh2RsaKey;
    private List<PpkKey> mSsh2KeyList;

    private bool mAddSsh2KeyReturnValue;

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
      return mAddSsh2KeyReturnValue;
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
      const string rsaKeyData = "AAADyBEAAAAHc3NoLXJzYQAAAQEAz8k2S0e868NhjaV" +
        "ctuPanK9ekQNzx7Y75cQOsbJi/1UqqinhsfSOfLHfQGpDwy1qm/DhWdhB3YWg1901BX" +
        "uCgLwPGQ1riVO4+6u0QFLYpLCFozbc0JvyWfTazluzrIZrDul/KxfoHzdlVNi0IV8XN" +
        "szHIDwoJVRthedBLE6mxpAjMewzkQDMtcOyrkG324ChJhcbgcVnlHfjH4Yl6coqu4tS" +
        "wdgR1vrgY9fT8FCwiib1fIIITt/ElHsuanpd8paAaBNjYtAuZR/wd+dQJelDePvaxjW" +
        "8BgNVL30lI6csTnyg7nLHwvUqh1iVogsH2XwvlOhklhbeKvcn8zppyemLOwAAAAMBAA" +
        "EAAAEAcS8mrx0VsMtN8W15Mnqtk5oHhjB+OfRvbjo80tjcCj/nLKgBtAEGOLBfbuQzo" +
        "zazEtzEtD8Tqcpnkg6CGklsDhnik3/26ug7JIQkfMFkF1m8geqZn9zCx/OT2MKk/b5+" +
        "xLG2PtAX9iEjxnMAtAjrSUOE2G9MYwE5Y65TlwIE4LWZ3nB5EE8HCd0vrXRzJEqqBP7" +
        "IiQI+HQHmeDmECvEMnIQhrK9g0Uo4o0AA9s4j7CgOhOK4/aoRHpc8YWygCGoIPQQWyG" +
        "o7Nfarnaly36IHmmwHaYvBeWnmdLtvX/zpyyj5vKnmlOSvDTfxYbWpvypGnsuRuekF2" +
        "NYphrfricOqOQAAAIAanwYTU7RE2cHGRA8G3q2Qhs3El6rRcIYTn+LiWIa6comVvuz3" +
        "P8l6AltxrzhXM2tyXAirGOnwEdslvvqP42Ha+ns1HLY/J7v66Vj07CgwovzuYbVNu6O" +
        "SwLGdetKxkVXoU/NiLtabjJqzr/TQGr0bVrK+BSrdelISA0mOrNkcsQAAAIEA6SA1cd" +
        "7dAjQAerXsKkodth+Ayhs+eG+ZCwbAE2YgkObMaDhCtX9JYSR3bS7f9v+pJRmL/HAMS" +
        "LdgYtmuA+yTPTY0Yg3nUY0dlrO8RAmbBQeL/k8zchBhJfSCr1m+NWwqBbeqXcTOLMUj" +
        "IT3YFnJHO0pm5c4KiQUJycvmIpkvTbcAAACBAOQsgKeLZqp7Tpd2bBSJVa2US8yxtc2" +
        "q7SWhJWNkvX1OwZUaRhLibobnI54szgljgno/g0Y3+CEqnTy0vVbeMPsEhNhEOsfNbs" +
        "XnU9NJU4jTS8cOG/1oOXsLqhfaElB4wk+P0ktEJ4W1XY7iQkdUAKg9yHMAy23TJsiwG" +
        "Y1nkC6dAAAAGi9ob21lL2tlZWFnZW50Ly5zc2gvaWRfcnNh";

      const string dsaKeyData = "AAAB6hEAAAAHc3NoLWRzcwAAAIEA9R3Vghcgm3FNH7C" +
        "1boqTFcHI67AWwto9VJDJzlIoeiyo93chOD18CAgpq561AnPTlKYaR5XZLPLN0P/8bj" +
        "/gDwX0sWnvjZMTeVu4CZqxxmT3hT6crRzNXUvOoAm1XgRY5sHffgEjQ7o49nIkcWzww" +
        "dXPB2QxkzfWr9IxSzUddoEAAAAVAObI6htk1CXUSnxMy9nfgcsJMGa9AAAAgEb3cjfQ" +
        "97FLPhidMp9OqvBNmxxpb5lADq64S7XXIxjAfky3iO992T/ROC81tq8cCt8UeqZRMXq" +
        "VIRKzGxY7DvCe4VEWT0frA4Nb3OEsGl+opHjmd/bwWX1y9X3pUdwGWczP2gXS9OF54d" +
        "QDFHc9K5pnH7C1LEsok6UN3gbfHReeAAAAgQDyWQSxdLd1hlgmZwar94vBXucYGo6qm" +
        "Zlu0qW9vsvBVkSmnzypLRPONYcbUZzw3MxtwsdRSabxFayqtYq1ggstbhSR410h9cFK" +
        "wDFnbcPf2exeO7SH8/PdryEz0lGnHp657yjKDAqn/pWtpHCkG9RT9ToWOmi7HmA4Wde" +
        "00PcdngAAABUAs1T5zEgZjLtHlOXQCpO30QIkLGsAAAAaL2hvbWUva2VlYWdlbnQvLn" +
        "NzaC9pZF9kc2E=";
      
      string actual;
      byte[] buffer = new byte[4096];
      byte[] decodedData, response;    
      MemoryStream stream = new MemoryStream(buffer);

      /* test adding rsa key */

      decodedData = PSUtil.FromBase64(rsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);      
      mAddSsh2KeyReturnValue = true;
      mAgent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentSucess, actual);

      /* test adding dsa key */

      stream.Position = 0;
      decodedData = PSUtil.FromBase64(dsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      mAddSsh2KeyReturnValue = true;
      mAgent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentSucess, actual);

      /* test AddSsh2Key returns false = ssh agent failure*/

      stream.Position = 0;
      mAddSsh2KeyReturnValue = false;
      mAgent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentFailure, actual);
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
