using dlech.PageantSharp;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using NUnit.Framework;
using PageantSharpNUnitTest.Properties;
using System.IO;
using System.Text;
using System.Collections.ObjectModel;

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
    private readonly byte[] cAgentFailure = { 0x00, 0x00, 0x00, 0x01, (byte)Agent.Message.SSH_AGENT_FAILURE };
    private readonly byte[] cAgentSucess = { 0x00, 0x00, 0x00, 0x01, (byte)Agent.Message.SSH_AGENT_SUCCESS };

    /* instance variables */
    byte[] mBuffer;
    MemoryStream mStream;
    BlobParser mParser;
    SshKey mRsa1Key;
    SshKey mRsaKey;
    SshKey mDsaKey;
    ReadOnlyCollection<ISshKey> mAllKeys;


    // since Agent is an abstract class, we need to create a trivial
    // implementation
    private class TestAgent : Agent
    {
      public TestAgent() { }

      public TestAgent(IEnumerable<ISshKey> keyList)
      {
        foreach (ISshKey key in keyList) {
          KeyList.Add(key);
        }
      }

      public override void Dispose() { }
    }
    

    [TestFixtureSetUp()]
    public void Setup()
    {
      mBuffer = new byte[4096];
      mStream = new MemoryStream(mBuffer);
      mParser = new BlobParser(mStream);

      SecureRandom secureRandom = new SecureRandom();
      KeyGenerationParameters keyGenParam =
        new KeyGenerationParameters(secureRandom, 512);

      RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
      rsaKeyPairGen.Init(keyGenParam);
      mRsa1Key = new SshKey();
      mRsa1Key.CipherKeyPair = rsaKeyPairGen.GenerateKeyPair();
      mRsa1Key.Version = SshVersion.SSH1;
      mRsa1Key.Comment = "SSH1 RSA test key";
      mRsaKey = new SshKey();
      mRsaKey.CipherKeyPair = mRsa1Key.CipherKeyPair;
      mRsaKey.Version = SshVersion.SSH2;
      mRsaKey.Comment = "SSH2 RSA test key";

      DsaParametersGenerator dsaParamGen = new DsaParametersGenerator();
      dsaParamGen.Init(512, 10, secureRandom);
      DsaParameters dsaParam = dsaParamGen.GenerateParameters();
      DsaKeyGenerationParameters dsaKeyGenParam =
        new DsaKeyGenerationParameters(secureRandom, dsaParam);
      DsaKeyPairGenerator dsaKeyPairGen = new DsaKeyPairGenerator();
      dsaKeyPairGen.Init(dsaKeyGenParam);
      mDsaKey = new SshKey();
      mDsaKey.CipherKeyPair = dsaKeyPairGen.GenerateKeyPair();
      mDsaKey.Version = SshVersion.SSH2;
      mDsaKey.Comment = "SSH2 DSA test key";

      // TODO add more key types here when they are implemented

      List<ISshKey> allKeys = new List<ISshKey>();
      allKeys.Add(mRsa1Key);
      allKeys.Add(mRsaKey);
      allKeys.Add(mDsaKey);      
      mAllKeys = allKeys.AsReadOnly();
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REQUEST_IDENTITIES()
    {
      Agent agent = new TestAgent(mAllKeys);      

      /* send request for SSH2 identities */
      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REQUEST_IDENTITIES);
      agent.AnswerMessage(mStream);
      RewindStream();

      /* check that we received proper response type */
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.Message,
        Is.EqualTo(Agent.Message.SSH2_AGENT_IDENTITIES_ANSWER));
      
      /* check that we received the correct key count */
      UInt32 actualKeyCount = mParser.ReadInt();
      List<ISshKey> ssh2KeyList =
        agent.KeyList.Where(key => key.Version == SshVersion.SSH2).ToList();
      int expectedSsh2KeyCount = ssh2KeyList.Count; 
      Assert.That(actualKeyCount, Is.EqualTo(expectedSsh2KeyCount));

      /* check that we have data for each key */
      for (int i = 0; i < actualKeyCount; i++) {
        byte[] actualPublicKeyBlob = mParser.ReadBlob().Data;
        byte[] expectedPublicKeyBlob =
          ssh2KeyList[i].CipherKeyPair.Public.ToBlob();
        Assert.That(actualPublicKeyBlob, Is.EqualTo(expectedPublicKeyBlob));
        string actualComment = mParser.ReadString();
        string expectedComment = ssh2KeyList[i].Comment;
        Assert.That(actualComment, Is.EqualTo(expectedComment));
      }
      /* verify that the overall response length is correct */
      Assert.That(header.BlobLength, Is.EqualTo(mStream.Position - 4));
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_SIGN_REQUEST()
    {
      const string signatureData = "this is the data that gets signed";
      byte[] signatureDataBytes = Encoding.UTF8.GetBytes(signatureData);

      Agent agent = new TestAgent(mAllKeys);

      /* test rsa signature */

      BlobBuilder builder = new BlobBuilder();
      builder.AddBlob(mRsaKey.CipherKeyPair.Public.ToBlob());
      builder.AddString(signatureData);
      builder.AddInt(0); // flags
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();

      /* check that proper response type was received */
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.Message,
                  Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));

      /* check that signature is valid */
      byte[] signatureBlob = mParser.ReadBlob().Data;
      BlobParser signatureParser = new BlobParser(signatureBlob);
      string algorithm = signatureParser.ReadString();
      Assert.That(algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_RSA.GetIdentifierString()));
      byte[] signature = signatureParser.ReadBlob().Data;
      ISigner rsaSigner = SignerUtilities.GetSigner("SHA-1withRSA");
      rsaSigner.Init(false, mRsaKey.CipherKeyPair.Public);
      rsaSigner.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
      bool rsaOk = rsaSigner.VerifySignature(signature);
      Assert.That(rsaOk, Is.True, "invalid signature");

      /* check that overall message length is correct */
      Assert.That(header.BlobLength, Is.EqualTo(mStream.Position - 4));

      /* test dsa signature */

      builder.Clear();
      builder.AddBlob(mDsaKey.CipherKeyPair.Public.ToBlob());
      builder.AddString(signatureData);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();

      /* check that proper response type was received */
      header = mParser.ReadHeader();
      Assert.That(header.Message,
                  Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
      signatureBlob = mParser.ReadBlob().Data;
      signatureParser = new BlobParser(signatureBlob);
      algorithm = Encoding.UTF8.GetString(signatureParser.ReadBlob().Data);
      Assert.That(algorithm, Is.EqualTo(PublicKeyAlgorithm.SSH_DSS.GetIdentifierString()));
      signature = signatureParser.ReadBlob().Data;
      ISigner dsaSigner = SignerUtilities.GetSigner("SHA-1withDSA");
      dsaSigner.Init(false, mDsaKey.CipherKeyPair.Public);
      dsaSigner.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
      bool dsaOk = dsaSigner.VerifySignature(signature);
      Assert.That(dsaOk, Is.True, "invalid signature");

      /* test key not found */

      agent.KeyList.Clear();
      builder.Clear();
      builder.AddBlob(mDsaKey.CipherKeyPair.Public.ToBlob());
      builder.AddString(signatureData);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();      
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
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


      Agent agent = new TestAgent();

      /* test adding rsa key */

      decodedData = PSUtil.FromBase64(rsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      ISshKey returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.CipherKeyPair.Public,
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.CipherKeyPair.Private,
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(rsaKeySize));
      Assert.That(returnedKey.Comment, Is.EqualTo(rsaKeyComment));
      Assert.That(returnedKey.Fingerprint.ToHexString(), Is.EqualTo(rsaKeyFingerprint));

      /* test adding dsa key */
      agent.KeyList.Clear();
      stream.Position = 0;
      decodedData = PSUtil.FromBase64(dsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.CipherKeyPair.Public,
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.CipherKeyPair.Private,
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(dsaKeySize));
      Assert.That(returnedKey.Comment, Is.EqualTo(dsaKeyComment));
      Assert.That(returnedKey.Fingerprint.ToHexString(), Is.EqualTo(dsaKeyFingerprint));

      /* test adding key that already is in KeyList does not create duplicate */
      int startingCount = agent.KeyList.Count();
      stream.Position = 0;
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      Assert.That(agent.KeyList.Count(), Is.EqualTo(startingCount));

      /* test locked => failure */
      agent.KeyList.Clear();
      agent.Lock(new byte[0]);
      stream.Position = 0;
      decodedData = PSUtil.FromBase64(dsaKeyData);
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentFailure));
      Assert.That(agent.KeyList.Count, Is.EqualTo(0));
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

      Agent agent = new TestAgent();
      SshKey testKey = PpkFile.ParseData((byte[])Resources.ssh2_rsa_no_passphrase_ppk.Clone(),
        null, delegate() { });
      agent.KeyList.Add(testKey);

      /* test remove key */

      stream.Position = 0;
      decodedData = PSUtil.FromBase64(request);
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentSucess));
      Assert.That(removeFingerprint, Is.EqualTo(requestFingerprint));

      /* test returns failure when locked */

      agent.Lock(new byte[0]);
      stream.Position = 0;
      decodedData = PSUtil.FromBase64(request);
      Array.Copy(decodedData, buffer, decodedData.Length);
      agent.AnswerMessage(stream);
      response = new byte[stream.Position];
      stream.Position = 0;
      stream.Read(response, 0, response.Length);
      Assert.That(response, Is.EqualTo(cAgentFailure));

    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REMOVE_ALL_IDENTITIES()
    {
      Agent agent = new TestAgent(mAllKeys);

      /* test that remove all keys removes keys */

      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
      agent.AnswerMessage(mStream);
      RewindStream();
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      int actualKeyCount = agent.KeyList.Count(key => key.Version != SshVersion.SSH2);
      int expectedKeyCount = mAllKeys.Count(key => key.Version != SshVersion.SSH2);
      Assert.That(actualKeyCount, Is.EqualTo(expectedKeyCount));

      /* test that remove all keys returns success even when there are no keys */
      agent.KeyList.Clear();
      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
      agent.AnswerMessage(mStream);
      RewindStream();
       header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));

      /* test that returns failure when locked */
      agent.Lock(new byte[0]);
      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
    }

    [Test()]
    public void TestAnswerSSH_AGENTC_LOCKandSSH_AGENTC_UNLOCK()
    {
      const string password = "password";

      Agent agent = new TestAgent();
      Assert.That(agent.IsLocked, Is.False, "Agent initial state was locked!");

      bool agentLockedCalled = false;
      Agent.BlobHeader replyHeader;

      Agent.LockEventHandler agentLocked =
        delegate(object aSender, Agent.LockEventArgs aEventArgs)
        {
          Assert.That(agentLockedCalled, Is.False,
            "LockEvent fired without resetting agentLockedCalled");
          agentLockedCalled = true;
        };

      agent.Locked += new Agent.LockEventHandler(agentLocked);

      
      /* test that unlock does nothing when already unlocked */

      PrepareLockMessage(false, password);
      agentLockedCalled = false;
      agent.AnswerMessage(mStream);
      RewindStream();
      replyHeader = mParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because agent was already unlocked");
      Assert.That(agent.IsLocked, Is.False, "Agent should still be unlocked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that locking works */

      PrepareLockMessage(true, password);
      agentLockedCalled = false;
      agent.AnswerMessage(mStream);
      RewindStream();
      replyHeader = mParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS),
        "Locking should have succeeded");
      Assert.That(agent.IsLocked, Is.True, "Agent should be locked");
      Assert.That(agentLockedCalled, Is.True,
        "agentLocked should have been called");


      /* test that trying to lock when already locked fails */

      PrepareLockMessage(true, password);
      agentLockedCalled = false;
      agent.AnswerMessage(mStream);
      RewindStream();
      replyHeader = mParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because agent was already unlocked");
      Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that unlocking with wrong password fails */

      PrepareLockMessage(false, password + "x");
      agentLockedCalled = false;
      agent.AnswerMessage(mStream);
      RewindStream();
      replyHeader = mParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because password was incorrect");
      Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that unlocking works */

      PrepareLockMessage(false, password);
      agentLockedCalled = false;
      agent.AnswerMessage(mStream);
      RewindStream();
      replyHeader = mParser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS),
        "Unlock should have succeeded");
      Assert.That(agent.IsLocked, Is.False, "Agent should be unlocked");
      Assert.That(agentLockedCalled, Is.True,
        "agentLocked should have been called");

      agent.Locked -= new Agent.LockEventHandler(agentLocked);
    }

    #region helper methods
    
    /// <summary>
    /// writes BlobBuilder data to beginning of Stream and resets Stream
    /// </summary>
    private void PrepareMessage(BlobBuilder aBuilder)
    {
      ResetStream();
      mStream.WriteBlob(aBuilder);
      RewindStream();
    }

    /// <summary>
    /// prepares a message with no data
    /// </summary>
    private void PrepareSimpleMessage(Agent.Message aMessage)
    {
      BlobBuilder builder = new BlobBuilder();
      builder.InsertHeader(aMessage);
      PrepareMessage(builder);
    }

    /// <summary>
    /// prepares a lock or unlock message with specified password
    /// </summary>
    private void PrepareLockMessage(bool aLock, string aPassword)
    {
      BlobBuilder builder = new BlobBuilder();
      builder.AddString(aPassword);
      if (aLock) {
        builder.InsertHeader(Agent.Message.SSH_AGENTC_LOCK);
      } else {
        builder.InsertHeader(Agent.Message.SSH_AGENTC_UNLOCK);
      }
      PrepareMessage(builder);
    }

    private void ResetStream()
    {
      Array.Clear(mBuffer, 0, mBuffer.Length);
      RewindStream();
    }

    private void RewindStream()
    {
      mStream.Position = 0;
    }
  }

  #endregion
}
