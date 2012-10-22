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

    private PpkKey mSsh2RsaKey, mSsh2DsaKey;
    private List<PpkKey> mSsh2KeyList;


    [TestFixtureSetUp()]
    public void Setup()
    {
      PpkFile.WarnOldFileFormatCallback WarnOldFileFormat = delegate()
      {
        // do nothing
      };

      mSsh2RsaKey = PpkFile.ParseData(Resources.ssh2_rsa_no_passphrase_ppk,
        null, WarnOldFileFormat);
      mSsh2DsaKey = PpkFile.ParseData(Resources.ssh2_dsa_no_passphrase_ppk,
        null, WarnOldFileFormat);
      mSsh2KeyList = new List<PpkKey>();
      mSsh2KeyList.Add(mSsh2RsaKey);
    }

    private class TestAgent : Agent
    {
      public TestAgent(GetSSH2KeyListCallback aGetSSH2KeyListCallback,
                       GetSSH2KeyCallback aGetSSH2KeyCallback,
                       AddSSH2KeyCallback aAddSSH2KeyCallback) :
        base(aGetSSH2KeyListCallback, aGetSSH2KeyCallback, aAddSSH2KeyCallback) { }
    }


    [Test()]
    public void TestAnswerSSH2_AGENTC_REQUEST_IDENTITIES()
    {
      string expected = "AAAAzAwAAAABAAAAlQAAAAdzc2gtcnNhAAAAASUAAACBAIVqnRL" +
        "P5c9a+C/GQAEu+q1+4Y966yP+hTZQcOhEW2tlRZp9gB8UMGZhx5qjPlLYmOe2p4Iw/X" +
        "0208y++AtPn/za0WPgWF39XBfruV5ozSsoK7CKt8jzGVeKvGHDf5bPQjnMpzkDCBJiR" +
        "ekNCw+xrfVL+co6nNgMu1VYRqmTZyHhAAAAKlBhZ2VhbnRTaGFycCB0ZXN0OiBTU0gy" +
        "LVJTQSwgbm8gcGFzc3BocmFzZQ==";

      Agent.GetSSH2KeyListCallback GetSsh2KeyList = delegate()
      {
        return mSsh2KeyList;
      };

      Agent agent = new TestAgent(GetSsh2KeyList, null, null);

      byte[] buffer = new byte[4096];
      BlobBuilder builder = new BlobBuilder();
      byte[] request = builder.GetBlob(OpenSsh.Message.SSH2_AGENTC_REQUEST_IDENTITIES);
      Array.Copy(request, buffer, 5);
      MemoryStream stream = new MemoryStream(buffer);
      agent.AnswerMessage(stream);
      byte[] response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      string actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(expected, actual);
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_SIGN_REQUEST()
    {
      const string rsaSignRequestData =
        "AAABlw0AAACVAAAAB3NzaC1yc2EAAAABJQAAAIEAhWqdEs/lz1r4L8ZAAS76rX7hj3r" +
        "rI/6FNlBw6ERba2VFmn2AHxQwZmHHmqM+UtiY57angjD9fTbTzL74C0+f/NrRY+BYXf" +
        "1cF+u5XmjNKygrsIq3yPMZV4q8YcN/ls9COcynOQMIEmJF6Q0LD7Gt9Uv5yjqc2Ay7V" +
        "VhGqZNnIeEAAAD1AAAAIDFXxpObEs3/LsBAw4dqt4zo16AD/GYi9T5GCVjtsCRwMgAA" +
        "AAhrZWVhZ2VudAAAAA5zc2gtY29ubmVjdGlvbgAAAAlwdWJsaWNrZXkBAAAAB3NzaC1" +
        "yc2EAAACVAAAAB3NzaC1yc2EAAAABJQAAAIEAhWqdEs/lz1r4L8ZAAS76rX7hj3rrI/" +
        "6FNlBw6ERba2VFmn2AHxQwZmHHmqM+UtiY57angjD9fTbTzL74C0+f/NrRY+BYXf1cF" +
        "+u5XmjNKygrsIq3yPMZV4q8YcN/ls9COcynOQMIEmJF6Q0LD7Gt9Uv5yjqc2Ay7VVhG" +
        "qZNnIeE=";

      const string rsaExpectedReply =
        "AAAAlA4AAACPAAAAB3NzaC1yc2EAAACAV3rOD8CwD+ewxJU+odr8vo6NyeEOxM64GO1" +
        "C7s93aXW+rPCxo0CUmbzDjva3p5U6v6clH39nmuWaEdVofy5MiS6u8d9wuaNgHVXw96" +
        "31iXllWVLE7ja6a+VWZeShMaO8xt5543lrUysNhhVo806aGE7WcKI+fcezwdswkQK0r" +
        "Ag=";

      const string dsaSignRequestData =
        "AAADzw0AAAGxAAAAB3NzaC1kc3MAAACBAMXDM56ty6fV+qDpMyZxobn5VB4L/E6zvOi" +
        "bUead6HBcOHUibA97EKgooUbqJ9qFUOhhw8TaFtN0UtTLZoHjOWN3JdyugK+f2HYIxv" +
        "hlvW608g0lfDU0G4KIXdZukTYm66C0jVSCIdHQ1Iz219JeaEZK00v6wEW7Pp7T7yE71" +
        "W65AAAAFQDcFrJ83lxI15fUnVl6TSYjB0H7IwAAAIAGatuDAwP1rkYqRH3MbwUTOpzr" +
        "k/qBYkWbM/8iJlYaWiHjl0rG0HxnwY8Dvb9Knk7Qp6KC8l58KRAiGMrOLBOfPntEgej" +
        "aXSejM6OARoOtt31IXfOMkbsjAFKFssN+RUDnTPvXPpcL5C3rO1Up4hO3FPqiJQJpL5" +
        "0gTHnDG2Q4BgAAAIA7w6OX/G/pXHDU0M7xXtTN2SOhFQwP8+Tc6h9/Yw/wM9zBXkqb5" +
        "bdlqy9vRx72/1DXOjH08PIbvza7HfOLkhRri0TYBDJbufQOlK4vQPqF0qhxkYfsgqrZ" +
        "BMBKbLKTZnNm+BW2dgu+QSud67b01IZPzS2i0Z4DgSja9vl3xongCwAAAhEAAAAgFRt" +
        "YDRrD3rmAJpZF7YItBpdkkUCMr4Djh349wyvemlIyAAAACGtlZWFnZW50AAAADnNzaC" +
        "1jb25uZWN0aW9uAAAACXB1YmxpY2tleQEAAAAHc3NoLWRzcwAAAbEAAAAHc3NoLWRzc" +
        "wAAAIEAxcMznq3Lp9X6oOkzJnGhuflUHgv8TrO86JtR5p3ocFw4dSJsD3sQqCihRuon" +
        "2oVQ6GHDxNoW03RS1MtmgeM5Y3cl3K6Ar5/YdgjG+GW9brTyDSV8NTQbgohd1m6RNib" +
        "roLSNVIIh0dDUjPbX0l5oRkrTS/rARbs+ntPvITvVbrkAAAAVANwWsnzeXEjXl9SdWX" +
        "pNJiMHQfsjAAAAgAZq24MDA/WuRipEfcxvBRM6nOuT+oFiRZsz/yImVhpaIeOXSsbQf" +
        "GfBjwO9v0qeTtCnooLyXnwpECIYys4sE58+e0SB6NpdJ6Mzo4BGg623fUhd84yRuyMA" +
        "UoWyw35FQOdM+9c+lwvkLes7VSniE7cU+qIlAmkvnSBMecMbZDgGAAAAgDvDo5f8b+l" +
        "ccNTQzvFe1M3ZI6EVDA/z5NzqH39jD/Az3MFeSpvlt2WrL29HHvb/UNc6MfTw8hu/Nr" +
        "sd84uSFGuLRNgEMlu59A6Uri9A+oXSqHGRh+yCqtkEwEpsspNmc2b4FbZ2C75BK53rt" +
        "vTUhk/NLaLRngOBKNr2+XfGieAL";
      

      PpkKey testKey = mSsh2RsaKey;
      Agent.GetSSH2KeyCallback GetSsh2Key = delegate(byte[] aFingerprint)
      {
        if (testKey != null) {
          string requestedFingerprint = PSUtil.ToHex(aFingerprint);
          string testKeyFingerprint = PSUtil.ToHex(OpenSsh.GetFingerprint(testKey.CipherKeyPair));
          Assert.AreEqual(requestedFingerprint, testKeyFingerprint);
        }
        return testKey;
      };
      Agent agent = new TestAgent(null, GetSsh2Key, null);
      byte[] buffer = new byte[4096];
      MemoryStream stream = new MemoryStream(buffer);

      /* test rsa signature */

      byte[] requestData = PSUtil.FromBase64(rsaSignRequestData);
      Array.Copy(requestData, buffer, requestData.Length);
      agent.AnswerMessage(stream);
      byte[] replyBytes = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(replyBytes, 0, replyBytes.Length);
      string actual = Encoding.UTF8.GetString(PSUtil.ToBase64(replyBytes));
      Assert.AreEqual(rsaExpectedReply, actual);

      /* test dsa signature */

      testKey = mSsh2DsaKey;
      requestData = PSUtil.FromBase64(dsaSignRequestData);
      Array.Copy(requestData, buffer, requestData.Length);
      stream.Position = 0;
      BlobParser parser = new BlobParser(stream);
      parser.ReadHeader();
      parser.Read();
      byte[] reqData = parser.Read();
      stream.Position = 0;
      agent.AnswerMessage(stream);
      replyBytes = new byte[stream.Position];
      stream.Position = 0;      
      OpenSsh.BlobHeader header = parser.ReadHeader();
      Assert.AreEqual(OpenSsh.Message.SSH2_AGENT_SIGN_RESPONSE, header.Message);
      byte[] signatureBlob = parser.Read();
      BlobParser signatureParser = new BlobParser(signatureBlob);
      signatureParser.Read(); // read algorithm
      byte[] signature = signatureParser.Read();
      ISigner dsaSigner = SignerUtilities.GetSigner("SHA-1withDSA");
      dsaSigner.Init(false, testKey.CipherKeyPair.Public);
      dsaSigner.BlockUpdate(reqData, 0, reqData.Length);
      bool dsaOk = dsaSigner.VerifySignature(signature);
      Assert.IsTrue(dsaOk, "invalid signature");

      /* test callback returns null */

      testKey = null;
      requestData = PSUtil.FromBase64(rsaSignRequestData);
      Array.Copy(requestData, buffer, requestData.Length);
      stream.Position = 0;
      agent.AnswerMessage(stream);
      replyBytes = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(replyBytes, 0, replyBytes.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(replyBytes));
      Assert.AreEqual(cAgentFailure, actual);

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
      const int rsaKeySize = 2048;
      const string rsaKeyComment = "/home/keeagent/.ssh/id_rsa";
      const string rsaKeyFingerprint = "c4:e7:45:dd:a9:1a:35:6a:1f:ef:71:1f:0a:b2:a6:eb";

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

      const int dsaKeySize = 1024;
      const string dsaKeyComment = "/home/keeagent/.ssh/id_dsa";
      const string dsaKeyFingerprint = "71:91:74:0f:42:05:39:04:58:02:a2:1b:51:ae:ab:cc";

      string actual;
      byte[] buffer = new byte[4096];
      byte[] decodedData, response;
      MemoryStream stream = new MemoryStream(buffer);
      PpkKey returnedKey = new PpkKey();
      bool addKeyReturnValue = true;

      Agent.AddSSH2KeyCallback AddSsh2Key = delegate(PpkKey aKey)
      {
        returnedKey = aKey;
        return addKeyReturnValue;
      };

      Agent agent = new TestAgent(null, null, AddSsh2Key);

      /* test adding rsa key */

      decodedData = PSUtil.FromBase64(rsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      addKeyReturnValue = true;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentSucess, actual);
      Assert.IsInstanceOfType(typeof(RsaKeyParameters),
        returnedKey.CipherKeyPair.Public);
      Assert.IsInstanceOfType(typeof(RsaKeyParameters),
        returnedKey.CipherKeyPair.Private);
      Assert.AreEqual(rsaKeySize, returnedKey.Size);
      Assert.AreEqual(rsaKeyComment, returnedKey.Comment);
      Assert.AreEqual(rsaKeyFingerprint,
        PSUtil.ToHex(OpenSsh.GetFingerprint(returnedKey.CipherKeyPair)));

      /* test adding dsa key */

      stream.Position = 0;
      decodedData = PSUtil.FromBase64(dsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      addKeyReturnValue = true;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentSucess, actual);
      Assert.IsInstanceOfType(typeof(DsaKeyParameters),
        returnedKey.CipherKeyPair.Public);
      Assert.IsInstanceOfType(typeof(DsaKeyParameters),
        returnedKey.CipherKeyPair.Private);
      Assert.AreEqual(dsaKeySize, returnedKey.Size);
      Assert.AreEqual(dsaKeyComment, returnedKey.Comment);
      Assert.AreEqual(dsaKeyFingerprint,
        PSUtil.ToHex(OpenSsh.GetFingerprint(returnedKey.CipherKeyPair)));

      /* test AddSsh2Key returns false => ssh agent failure*/

      stream.Position = 0;
      addKeyReturnValue = false;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.AreEqual(cAgentFailure, actual);
    }

  }
}
