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
    // these are 'constants', so don't modify the values!
    private readonly byte[] cAgentFailure =
      { 0x00, 0x00, 0x00, 0x01, (byte)OpenSsh.Message.SSH_AGENT_FAILURE };
    private readonly byte[] cAgentSucess =
      { 0x00, 0x00, 0x00, 0x01, (byte)OpenSsh.Message.SSH_AGENT_SUCCESS };

    // since Agent is an abstract class, we need to create a trivial
    // implementation
    private class TestAgent : Agent
    {
      public TestAgent(Callbacks aCallbacks) :
        base(aCallbacks) { }

      public override void Dispose() { }
    }


    [Test()]
    public void TestAnswerSSH2_AGENTC_REQUEST_IDENTITIES()
    {
      string expected = "AAAAzAwAAAABAAAAlQAAAAdzc2gtcnNhAAAAASUAAACBAIVqnRL" +
        "P5c9a+C/GQAEu+q1+4Y966yP+hTZQcOhEW2tlRZp9gB8UMGZhx5qjPlLYmOe2p4Iw/X" +
        "0208y++AtPn/za0WPgWF39XBfruV5ozSsoK7CKt8jzGVeKvGHDf5bPQjnMpzkDCBJiR" +
        "ekNCw+xrfVL+co6nNgMu1VYRqmTZyHhAAAAKlBhZ2VhbnRTaGFycCB0ZXN0OiBTU0gy" +
        "LVJTQSwgbm8gcGFzc3BocmFzZQ==";

      SshKey ssh2RsaKey =
        PpkFile.ParseData((byte[])Resources.ssh2_rsa_no_passphrase_ppk.Clone(),
                           null, delegate() { });
      List<SshKey> ssh2KeyList = new List<SshKey>();
      ssh2KeyList.Add(ssh2RsaKey);

      Agent.GetSSHKeyListCallback GetSsh2KeyList = delegate()
      {
        return ssh2KeyList;
      };

      Agent.Callbacks callbacks = new Agent.Callbacks();
      callbacks.getSSH2KeyList = GetSsh2KeyList;
      Agent agent = new TestAgent(callbacks);

      byte[] buffer = new byte[4096];
      MemoryStream stream = new MemoryStream(buffer);

      PrepareSimpleMessage(OpenSsh.Message.SSH2_AGENTC_REQUEST_IDENTITIES, stream);
      agent.AnswerMessage(stream);
      byte[] response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      string actual = Encoding.UTF8.GetString(PSUtil.ToBase64(response));
      Assert.That(actual, Is.EqualTo(expected));
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

      bool getSsh2KeyCalled = false;

      SshKey testKey = null;
      Agent.GetSSHKeyCallback GetSsh2Key = delegate(byte[] aFingerprint)
      {
        getSsh2KeyCalled = true;
        if (testKey != null) {
          string requestedFingerprint = aFingerprint.ToHexString();
          Assert.That(testKey.Fingerprint, Is.EqualTo(requestedFingerprint));
        }
        return testKey;
      };
      Agent.Callbacks callbacks = new Agent.Callbacks();
      callbacks.getSSH2Key = GetSsh2Key;
      Agent agent = new TestAgent(callbacks);
      byte[] buffer = new byte[4096];
      MemoryStream stream = new MemoryStream(buffer);
      BlobParser parser = new BlobParser(stream);

      /* test rsa signature */

      testKey = PpkFile.ParseData((byte[])Resources.ssh2_rsa_no_passphrase_ppk.Clone(),
                                         null, delegate() { });
      byte[] requestData = PSUtil.FromBase64(rsaSignRequestData);
      Array.Copy(requestData, buffer, requestData.Length);
      stream.Position = 0;
      parser.ReadHeader();
      parser.ReadBlob(); // read public key
      PinnedByteArray reqData = parser.ReadBlob();
      stream.Position = 0;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      OpenSsh.BlobHeader header = parser.ReadHeader();
      Assert.That(header.Message,
                  Is.EqualTo(OpenSsh.Message.SSH2_AGENT_SIGN_RESPONSE));
      byte[] signatureBlob = parser.ReadBlob().Data;
      BlobParser signatureParser = new BlobParser(signatureBlob);
      string algorithm = signatureParser.ReadString();
      Assert.That(algorithm, Is.EqualTo(OpenSsh.PublicKeyAlgorithms.ssh_rsa));
      byte[] signature = signatureParser.ReadBlob().Data;
      ISigner rsaSigner = SignerUtilities.GetSigner("SHA-1withRSA");
      rsaSigner.Init(false, testKey.CipherKeyPair.Public);
      rsaSigner.BlockUpdate(reqData.Data, 0, reqData.Data.Length);
      bool rsaOk = rsaSigner.VerifySignature(signature);
      Assert.That(rsaOk, Is.True, "invalid signature");

      /* test dsa signature */

      testKey = PpkFile.ParseData(Resources.ssh2_dsa_no_passphrase_ppk,
                                  null, delegate() { });
      requestData = PSUtil.FromBase64(dsaSignRequestData);
      Array.Copy(requestData, buffer, requestData.Length);
      stream.Position = 0;
      parser.ReadHeader();
      parser.ReadBlob();
      reqData = parser.ReadBlob();
      stream.Position = 0;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      header = parser.ReadHeader();
      Assert.That(header.Message,
                  Is.EqualTo(OpenSsh.Message.SSH2_AGENT_SIGN_RESPONSE));
      signatureBlob = parser.ReadBlob().Data;
      signatureParser = new BlobParser(signatureBlob);
      algorithm = Encoding.UTF8.GetString(signatureParser.ReadBlob().Data);
      Assert.That(algorithm, Is.EqualTo(OpenSsh.PublicKeyAlgorithms.ssh_dss));
      signature = signatureParser.ReadBlob().Data;
      ISigner dsaSigner = SignerUtilities.GetSigner("SHA-1withDSA");
      dsaSigner.Init(false, testKey.CipherKeyPair.Public);
      dsaSigner.BlockUpdate(reqData.Data, 0, reqData.Data.Length);
      bool dsaOk = dsaSigner.VerifySignature(signature);
      Assert.That(dsaOk, Is.True, "invalid signature");

      /* test callback returns null */

      getSsh2KeyCalled = false;
      testKey = null;
      requestData = PSUtil.FromBase64(rsaSignRequestData);
      Array.Copy(requestData, buffer, requestData.Length);
      stream.Position = 0;
      agent.AnswerMessage(stream);
      byte[] replyBytes = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(replyBytes, 0, replyBytes.Length);
      Assert.That(replyBytes, Is.EqualTo(cAgentFailure));
      Assert.That(getSsh2KeyCalled, Is.True, "Callback was not called");
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
      const string rsaKeyFingerprint =
        "c4:e7:45:dd:a9:1a:35:6a:1f:ef:71:1f:0a:b2:a6:eb";

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
      const string dsaKeyFingerprint =
        "71:91:74:0f:42:05:39:04:58:02:a2:1b:51:ae:ab:cc";

      byte[] buffer = new byte[4096];
      byte[] decodedData, response;
      MemoryStream stream = new MemoryStream(buffer);
      SshKey returnedKey = new SshKey();
      bool addKeyCalled = false;
      bool addKeyReturnValue = true;

      Agent.AddSSHKeyCallback AddSsh2Key = delegate(SshKey aKey)
      {
        addKeyCalled = true;
        returnedKey = aKey;
        return addKeyReturnValue;
      };
      Agent.Callbacks callbacks = new Agent.Callbacks();
      callbacks.addSSH2Key = AddSsh2Key;
      Agent agent = new TestAgent(callbacks);

      /* test adding rsa key */

      decodedData = PSUtil.FromBase64(rsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      addKeyReturnValue = true;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      Assert.That(returnedKey.CipherKeyPair.Public,
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.CipherKeyPair.Private,
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(rsaKeySize));
      Assert.That(returnedKey.Comment, Is.EqualTo(rsaKeyComment));
      Assert.That(returnedKey.Fingerprint, Is.EqualTo(rsaKeyFingerprint));

      /* test adding dsa key */

      stream.Position = 0;
      decodedData = PSUtil.FromBase64(dsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      addKeyReturnValue = true;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      Assert.That(returnedKey.CipherKeyPair.Public,
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.CipherKeyPair.Private,
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(dsaKeySize));
      Assert.That(returnedKey.Comment, Is.EqualTo(dsaKeyComment));
      Assert.That(returnedKey.Fingerprint, Is.EqualTo(dsaKeyFingerprint));

      /* test AddSsh2Key returns false => ssh agent failure*/

      stream.Position = 0;
      decodedData = PSUtil.FromBase64(dsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      addKeyCalled = false;
      addKeyReturnValue = false;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentFailure));
      Assert.That(addKeyCalled, Is.True, "Callback was not called");
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REMOVE_IDENTITY()
    {
      const string request =
        "AAABHBIAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDPyTZLR7zrw2GNpVy249qcr16" +
        "RA3PHtjvlxA6xsmL/VSqqKeGx9I58sd9AakPDLWqb8OFZ2EHdhaDX3TUFe4KAvA8ZDW" +
        "uJU7j7q7RAUtiksIWjNtzQm/JZ9NrOW7OshmsO6X8rF+gfN2VU2LQhXxc2zMcgPCglV" +
        "G2F50EsTqbGkCMx7DORAMy1w7KuQbfbgKEmFxuBxWeUd+MfhiXpyiq7i1LB2BHW+uBj" +
        "19PwULCKJvV8gghO38SUey5qel3yloBoE2Ni0C5lH/B351Al6UN4+9rGNbwGA1UvfSU" +
        "jpyxOfKDucsfC9SqHWJWiCwfZfC+U6GSWFt4q9yfzOmnJ6Ys7";
      const string requestFingerprint =
        "c4:e7:45:dd:a9:1a:35:6a:1f:ef:71:1f:0a:b2:a6:eb";

      byte[] buffer = new byte[4096];
      byte[] decodedData, response;
      MemoryStream stream = new MemoryStream(buffer);
      string removeFingerprint = null;
      bool removeKeyCalled = false;
      bool removeKeyReturnValue = true;

      Agent.RemoveSSHKeyCallback RemoveSsh2Key = delegate(byte[] aFingerprint)
      {
        removeKeyCalled = true;
        removeFingerprint = aFingerprint.ToHexString();
        return removeKeyReturnValue;
      };
      Agent.Callbacks callbacks = new Agent.Callbacks();
      callbacks.removeSSH2Key = RemoveSsh2Key;
      Agent agent = new TestAgent(callbacks);

      /* test remove key */

      stream.Position = 0;
      decodedData = PSUtil.FromBase64(request);
      Array.Copy(decodedData, buffer, decodedData.Length);
      removeKeyReturnValue = true;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      Assert.That(removeFingerprint, Is.EqualTo(requestFingerprint));

      /* test callback returns false */

      stream.Position = 0;
      removeKeyCalled = false;
      removeKeyReturnValue = false;
      decodedData = PSUtil.FromBase64(request);
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentFailure));
      Assert.That(removeKeyCalled, Is.True, "Callback was not called.");

    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REMOVE_ALL_IDENTITIES()
    {
      byte[] buffer = new byte[4096];
      byte[] response;
      MemoryStream stream = new MemoryStream(buffer);
      bool removeAllKeysCalled = false;
      bool removeAllKeysReturnValue = true;

      Agent.RemoveAllSSHKeysCallback RemoveAllSsh2Keys = delegate()
      {
        removeAllKeysCalled = true;
        return removeAllKeysReturnValue;
      };
      Agent.Callbacks callbacks = new Agent.Callbacks();
      callbacks.removeAllSSH2Keys = RemoveAllSsh2Keys;
      Agent agent = new TestAgent(callbacks);

      /* test remove all keys */

      PrepareSimpleMessage(OpenSsh.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES, stream);
      removeAllKeysReturnValue = true;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));

      /* test callback returns false */

      PrepareSimpleMessage(OpenSsh.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES, stream);
      removeAllKeysCalled = false;
      removeAllKeysReturnValue = false;
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentFailure));
      Assert.That(removeAllKeysCalled, Is.True, "Callback was not called.");

    }

    [Test()]
    public void TestAnswerSSH_AGENTC_LOCKandSSH_AGENTC_UNLOCK()
    {
      const string password = "password";

      Agent.Callbacks callbacks = new Agent.Callbacks();
      Agent agent = new TestAgent(callbacks);
      Assert.That(agent.IsLocked, Is.False, "Agent initial state was locked!");

      bool agentLockedCalled = false;
      OpenSsh.BlobHeader replyHeader;

      Agent.LockEventHandler agentLocked =
        delegate(object aSender, Agent.LockEventArgs aEventArgs)
        {
          Assert.That(agentLockedCalled, Is.False,
            "LockEvent fired without resetting agentLockedCalled");
          agentLockedCalled = true;
        };

      agent.Locked += new Agent.LockEventHandler(agentLocked);

      byte[] buffer = new byte[4096];
      MemoryStream stream = new MemoryStream(buffer);
      BlobParser messageParser = new BlobParser(stream);


      /* test that unlock does nothing when already unlocked */

      PrepareLockMessage(false, password, stream);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      replyHeader = messageParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(OpenSsh.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because agent was already unlocked");
      Assert.That(agent.IsLocked, Is.False, "Agent should still be unlocked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that locking works */

      PrepareLockMessage(true, password, stream);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      replyHeader = messageParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(OpenSsh.Message.SSH_AGENT_SUCCESS),
        "Locking should have succeeded");
      Assert.That(agent.IsLocked, Is.True, "Agent should be locked");
      Assert.That(agentLockedCalled, Is.True,
        "agentLocked should have been called");


      /* test that trying to lock when already locked fails */

      PrepareLockMessage(true, password, stream);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      replyHeader = messageParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(OpenSsh.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because agent was already unlocked");
      Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that unlocking with wrong password fails */

      PrepareLockMessage(false, password + "x", stream);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      replyHeader = messageParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(OpenSsh.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because password was incorrect");
      Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that unlocking works */

      PrepareLockMessage(false, password, stream);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      stream.Position = 0;
      replyHeader = messageParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(OpenSsh.Message.SSH_AGENT_SUCCESS),
        "Unlock should have succeeded");
      Assert.That(agent.IsLocked, Is.False, "Agent should be unlocked");
      Assert.That(agentLockedCalled, Is.True,
        "agentLocked should have been called");

      agent.Locked -= new Agent.LockEventHandler(agentLocked);
    }

    /// <summary>
    /// writes BlobBuilder data to beginning of Stream and resets Stream
    /// </summary>
    private void PrepareMessage(BlobBuilder aBuilder, Stream aStream)
    {
      aStream.Position = 0;
      aStream.WriteBlob(aBuilder);
      aStream.Position = 0;
    }

    /// <summary>
    /// prepares a message with no data
    /// </summary>
    private void PrepareSimpleMessage(OpenSsh.Message aMessage, Stream aStream)
    {
      BlobBuilder builder = new BlobBuilder();
      builder.InsertHeader(aMessage);
      PrepareMessage(builder, aStream);
    }

    /// <summary>
    /// prepares a lock or unlock message with specified password
    /// </summary>
    private void PrepareLockMessage(bool aLock, string aPassword, Stream aStream)
    {
      BlobBuilder builder = new BlobBuilder();
      builder.AddString(aPassword);
      if (aLock) {
        builder.InsertHeader(OpenSsh.Message.SSH_AGENTC_LOCK);
      } else {
        builder.InsertHeader(OpenSsh.Message.SSH_AGENTC_UNLOCK);
      }
      PrepareMessage(builder, aStream);
    }
  }
}
