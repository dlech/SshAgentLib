using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using dlech.SshAgentLib;
using System.IO;
using System.Collections.ObjectModel;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1;

namespace dlech.SshAgentLibTests
{
  [TestFixture()]
  public class AgentClientTest
  {

    private static SshKey mRsa1Key, mRsaKey, mDsaKey,
      mEcdsa256Key, mEcdsa384Key, mEcdsa521Key;
    private static ReadOnlyCollection<SshKey> mAllKeys;

    private class TestAgentClient : AgentClient
    {
      public Agent Agent { get; private set; }

      public TestAgentClient()
      {
        Agent = new TestAgent();
      }

      public override void SendMessage(byte[] aMessage, out byte[] aReply)
      {
        var buffer = new byte[4096];
        Array.Copy(aMessage, buffer, aMessage.Length);
        var messageStream = new MemoryStream(buffer);
        Agent.AnswerMessage(messageStream);
        aReply = new byte[messageStream.Position];
        Array.Copy(buffer, aReply, aReply.Length);
      }
    }

    private class TestAgent : Agent
    {
      public override void Dispose() { }
    }

    static AgentClientTest()
    {
      mRsa1Key = KeyGenerator.CreateKey(SshVersion.SSH1,
        PublicKeyAlgorithm.SSH_RSA, "SSH1 RSA test key");
      mRsaKey = KeyGenerator.CreateKey(SshVersion.SSH2,
     PublicKeyAlgorithm.SSH_RSA, "SSH2 RSA test key");
      mDsaKey = KeyGenerator.CreateKey(SshVersion.SSH2,
      PublicKeyAlgorithm.SSH_DSS, "SSH2 DSA test key");
      mEcdsa256Key = KeyGenerator.CreateKey(SshVersion.SSH2,
      PublicKeyAlgorithm.ECDSA_SHA2_NISTP256, "SSH2 ECDSA 256 test key");
      mEcdsa384Key = KeyGenerator.CreateKey(SshVersion.SSH2,
       PublicKeyAlgorithm.ECDSA_SHA2_NISTP384, "SSH2 ECDSA 384 test key");
      mEcdsa521Key = KeyGenerator.CreateKey(SshVersion.SSH2,
       PublicKeyAlgorithm.ECDSA_SHA2_NISTP521, "SSH2 ECDSA 521 test key");

      List<SshKey> keyList = new List<SshKey>();
      keyList.Add(mRsa1Key);
      keyList.Add(mRsaKey);
      keyList.Add(mDsaKey);
      keyList.Add(mEcdsa256Key);
      keyList.Add(mEcdsa384Key);
      keyList.Add(mEcdsa521Key);
      mAllKeys = keyList.AsReadOnly();
    }

    [Test()]
    public void TestAddConstrainedKey()
    {
      var agentClient = new TestAgentClient();
      agentClient.Agent.ConfirmUserPermissionCallback =
        delegate(ISshKey aKey) { return true; };
      bool result;
      Agent.KeyConstraint constraint;
      List<Agent.KeyConstraint> constraints = new List<Agent.KeyConstraint>();

      constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
      constraints.Add(constraint);
      result = agentClient.AddConstrainedKey(mRsaKey, constraints);
      Assert.That(result, Is.True);
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(1));
      Assert.That(agentClient.Agent.KeyList.First().Constraints.Count,
        Is.EqualTo(1));
      Assert.That(agentClient.Agent.KeyList.First().Constraints.First().Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));

      constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
      constraint.Data = (uint)10;
      constraints.Clear();
      constraints.Add(constraint);
      result = agentClient.AddConstrainedKey(mRsaKey, constraints);
      Assert.That(result, Is.True);
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(1));
      Assert.That(agentClient.Agent.KeyList.First().Constraints.Count,
        Is.EqualTo(1));
      Assert.That(agentClient.Agent.KeyList.First().Constraints.First().Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME));
    }

    [Test()]
    public void TestAddKey()
    {
      var agentClient = new TestAgentClient();
      bool result;
      int keyCount = 0;

      foreach (var key in mAllKeys.Where(key => key.Version == SshVersion.SSH2)) {
        result = agentClient.AddKey(key);
        Assert.That(result, Is.True);
        keyCount += 1;
        Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(keyCount));
        Assert.That(agentClient.Agent.KeyList
          .Get(key.Version, key.GetPublicKeyBlob()), Is.Not.Null);
      }
    }

    [Test()]
    public void TesListKeys()
    {
      var agentClient = new TestAgentClient();
      ICollection<ISshKey> keyList;
      bool result;

      foreach (var key in mAllKeys) {
        agentClient.Agent.AddKey(key);
      }
      result = agentClient.ListKeys(SshVersion.SSH2, out keyList);
      Assert.That(result, Is.True);
      var expectedKeyList = mAllKeys.Where(key => key.Version == SshVersion.SSH2);
      Assert.That(keyList.Count, Is.EqualTo(expectedKeyList.Count()));
      foreach (var key in expectedKeyList) {
        Assert.That(keyList.Get(key.Version, key.GetPublicKeyBlob()), Is.Not.Null);
      }
    }

    [Test()]
    public void TestRemoveAllKeys()
    {
      var agentClient = new TestAgentClient();
      bool result;

      /* test SSH1 */
      agentClient.Agent.AddKey(mRsa1Key);
      agentClient.Agent.AddKey(mRsaKey);
      result = agentClient.RemoveAllKeys(SshVersion.SSH1);
      Assert.That(result, Is.True);
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(1));

      /* test SSH2 */
      agentClient.Agent.AddKey(mRsa1Key);
      agentClient.Agent.AddKey(mRsaKey);
      result = agentClient.RemoveAllKeys(SshVersion.SSH2);
      Assert.That(result, Is.True);
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(1));

      /* test remove *all* keys */
      agentClient.Agent.AddKey(mRsa1Key);
      agentClient.Agent.AddKey(mRsaKey);
      agentClient.RemoveAllKeys();
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(0));
    }

    [Test()]
    public void TestRemoveKey()
    {
      var agentClient = new TestAgentClient();
      bool result;

      /* test SSH1 */
      //agentClient.Agent.AddKey(mRsa1Key);
      //result = agentClient.RemoveKey(mRsa1Key);
      //Assert.That(result, Is.True);
      //Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(0));

      /* test SSH2 */
      agentClient.Agent.AddKey(mRsaKey);
      result = agentClient.RemoveKey(mRsaKey);
      Assert.That(result, Is.True);
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(0));

      /* test key not found */
      agentClient.Agent.AddKey(mRsaKey);
      result = agentClient.RemoveKey(mDsaKey);
      Assert.That(result, Is.False);
      Assert.That(agentClient.Agent.KeyList.Count, Is.EqualTo(1));
    }

    [Test()]
    public void TestSignRequest()
    {
      var passphrase = Encoding.UTF8.GetBytes("passphrase");
      var agentClient = new TestAgentClient();
      var data = Encoding.UTF8.GetBytes("Data to be signed");
      byte[] signature;
      bool result;

      foreach (var key in mAllKeys.Where(key => key.Version == SshVersion.SSH2)) {
        agentClient.Agent.AddKey(key);
        result = agentClient.SignRequest(key, data, out signature);
        Assert.That(result, Is.True);
        BlobParser signatureParser = new BlobParser(signature);
        var algorithm = signatureParser.ReadString();
        Assert.That(algorithm, Is.EqualTo(key.Algorithm.GetIdentifierString()));
        signature = signatureParser.ReadBlob().Data;
        if (key.Algorithm == PublicKeyAlgorithm.SSH_RSA) {
          Assert.That(signature.Length == key.Size / 8);
        } else if (key.Algorithm == PublicKeyAlgorithm.SSH_DSS) {
          Assert.That(signature.Length, Is.EqualTo(40));
          var r = new BigInteger(1, signature, 0, 20);
          var s = new BigInteger(1, signature, 20, 20);
          var seq = new DerSequence(new DerInteger(r), new DerInteger(s));
          signature = seq.GetDerEncoded();
        } else if (key.Algorithm == PublicKeyAlgorithm.ECDSA_SHA2_NISTP256 ||
          key.Algorithm == PublicKeyAlgorithm.ECDSA_SHA2_NISTP384 ||
          key.Algorithm == PublicKeyAlgorithm.ECDSA_SHA2_NISTP521) {
          Assert.That(signature.Length, Is.AtLeast(key.Size / 4 + 8));
          Assert.That(signature.Length, Is.AtMost(key.Size / 4 + 10));
          BlobParser parser = new BlobParser(signature);
          var r = new BigInteger(parser.ReadBlob().Data);
          var s = new BigInteger(parser.ReadBlob().Data);
          var seq = new DerSequence(new DerInteger(r), new DerInteger(s));
          signature = seq.GetDerEncoded();
        }
        var signer = key.GetSigner();
        signer.Init(false, key.GetPublicKeyParameters());
        signer.BlockUpdate(data, 0, data.Length);
        result = signer.VerifySignature(signature);
        Assert.That(result, Is.True);
      }
    }

    [Test()]
    public void TestLockUnlock()
    {
      var passphrase = Encoding.UTF8.GetBytes("passphrase");
      var agentClient = new TestAgentClient();
      bool result;

      /* verify that locking works */
      result = agentClient.Lock(passphrase);
      Assert.That(result, Is.True);

      /* verify that locking already locked agent fails */
      result = agentClient.Lock(passphrase);
      Assert.That(result, Is.False);

      /* verify that unlocking works */
      result = agentClient.Unlock(passphrase);
      Assert.That(result, Is.True);

      /* verify that unlocking already unlocked agent fails */
      result = agentClient.Unlock(passphrase);
      Assert.That(result, Is.False);

      /* try with null passphrase */
      result = agentClient.Lock(null);
      Assert.That(result, Is.True);
      result = agentClient.Unlock(null);
      Assert.That(result, Is.True);

      /* verify that bad passphrase fails */
      result = agentClient.Lock(passphrase);
      Assert.That(result, Is.True);
      result = agentClient.Unlock(null);
      Assert.That(result, Is.False);
    }

  }
}
