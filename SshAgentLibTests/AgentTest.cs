using dlech.SshAgentLib;
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
using dlech.SshAgentLibTests.Properties;
using System.IO;
using System.Text;
using System.Collections.ObjectModel;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1;
using System.Threading;

namespace dlech.SshAgentLibTests
{

  /// <summary>
  ///This is a test class for Agent class and is intended
  ///to contain all Agent Unit Tests
  ///</summary>
  [TestFixture()]
  public class AgentTest
  {
    private const string cTestNotImplemented = "Test not implemented";

    /* instance variables */
    static byte[] mBuffer;
    static MemoryStream mStream;
    static BlobParser mParser;
    static SshKey mRsa1Key;
    static SshKey mRsaKey;
    static SshKey mDsaKey;
    static SshKey mEcdsa256Key;
    static SshKey mEcdsa384Key;
    static SshKey mEcdsa521Key;
    static ReadOnlyCollection<ISshKey> mAllKeys;


    // since Agent is an abstract class, we need to create a trivial
    // implementation
    private class TestAgent : Agent
    {
      public TestAgent() { }

      public TestAgent(IEnumerable<ISshKey> keyList)
      {
        foreach (ISshKey key in keyList) {
          AddKey(key);
        }
      }

      public override void Dispose() { }
    }


    static AgentTest()
    {
      mBuffer = new byte[4096];
      mStream = new MemoryStream(mBuffer);
      mParser = new BlobParser(mStream);

      SecureRandom secureRandom = new SecureRandom();
      KeyGenerationParameters keyGenParam =
        new KeyGenerationParameters(secureRandom, 512);

      RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
      rsaKeyPairGen.Init(keyGenParam);
      AsymmetricCipherKeyPair keyPair = rsaKeyPairGen.GenerateKeyPair();
      mRsa1Key = new SshKey(SshVersion.SSH1, keyPair);
      mRsa1Key.Comment = "SSH1 RSA test key";
      mRsaKey = new SshKey(SshVersion.SSH2, keyPair);
      mRsaKey.Comment = "SSH2 RSA test key";

      DsaParametersGenerator dsaParamGen = new DsaParametersGenerator();
      dsaParamGen.Init(512, 10, secureRandom);
      DsaParameters dsaParam = dsaParamGen.GenerateParameters();
      DsaKeyGenerationParameters dsaKeyGenParam =
        new DsaKeyGenerationParameters(secureRandom, dsaParam);
      DsaKeyPairGenerator dsaKeyPairGen = new DsaKeyPairGenerator();
      dsaKeyPairGen.Init(dsaKeyGenParam);
      keyPair = dsaKeyPairGen.GenerateKeyPair();
      mDsaKey = new SshKey(SshVersion.SSH2, keyPair);
      mDsaKey.Comment = "SSH2 DSA test key";

      X9ECParameters ecdsa256X9Params =
        SecNamedCurves.GetByName("secp256r1");
      ECDomainParameters ecdsa256DomainParams =
        new ECDomainParameters(ecdsa256X9Params.Curve, ecdsa256X9Params.G,
          ecdsa256X9Params.N, ecdsa256X9Params.H);
      ECKeyGenerationParameters ecdsa256GenParams =
        new ECKeyGenerationParameters(ecdsa256DomainParams, secureRandom);
      ECKeyPairGenerator ecdsa256Gen = new ECKeyPairGenerator();
      ecdsa256Gen.Init(ecdsa256GenParams);
      keyPair = ecdsa256Gen.GenerateKeyPair();
      mEcdsa256Key = new SshKey(SshVersion.SSH2, keyPair);
      mEcdsa256Key.Comment = "SSH2 ECDSA 256 test key";

      X9ECParameters ecdsa384X9Params =
        SecNamedCurves.GetByName("secp384r1");
      ECDomainParameters ecdsa384DomainParams =
        new ECDomainParameters(ecdsa384X9Params.Curve, ecdsa384X9Params.G,
          ecdsa384X9Params.N, ecdsa384X9Params.H);
      ECKeyGenerationParameters ecdsa384GenParams =
        new ECKeyGenerationParameters(ecdsa384DomainParams, secureRandom);
      ECKeyPairGenerator ecdsa384Gen = new ECKeyPairGenerator();
      ecdsa384Gen.Init(ecdsa384GenParams);
      keyPair = ecdsa384Gen.GenerateKeyPair();
      mEcdsa384Key = new SshKey(SshVersion.SSH2, keyPair);
      mEcdsa384Key.Comment = "SSH2 ECDSA 384 test key";

      X9ECParameters ecdsa521X9Params =
        SecNamedCurves.GetByName("secp521r1");
      ECDomainParameters ecdsa521DomainParams =
        new ECDomainParameters(ecdsa521X9Params.Curve, ecdsa521X9Params.G,
          ecdsa521X9Params.N, ecdsa521X9Params.H);
      ECKeyGenerationParameters ecdsa521GenParams =
        new ECKeyGenerationParameters(ecdsa521DomainParams, secureRandom);
      ECKeyPairGenerator ecdsa521Gen = new ECKeyPairGenerator();
      ecdsa521Gen.Init(ecdsa521GenParams);
      keyPair = ecdsa521Gen.GenerateKeyPair();
      mEcdsa521Key = new SshKey(SshVersion.SSH2, keyPair);
      mEcdsa521Key.Comment = "SSH2 ECDSA 521 test key";
           
      List<ISshKey> allKeys = new List<ISshKey>();
      allKeys.Add(mRsa1Key);
      allKeys.Add(mRsaKey);
      allKeys.Add(mDsaKey);
      allKeys.Add(mEcdsa256Key);
      allKeys.Add(mEcdsa384Key);
      allKeys.Add(mEcdsa521Key);
      mAllKeys = allKeys.AsReadOnly();
    }

    [Test()]
    public void TestAnswerUnknownRequest()
    {
      Agent agent = new TestAgent();

      byte unknownMessage = 0xFF;
      Assert.That(Enum.IsDefined(typeof(Agent.Message), unknownMessage), Is.False);
      Assert.That(unknownMessage, Is.Not.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      PrepareSimpleMessage(unchecked((Agent.Message)(unknownMessage)));
      agent.AnswerMessage(mStream);
      RewindStream();
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
    }

    [Test()]
    [Ignore(cTestNotImplemented)]
    public void TestAnswerSSH1_AGENTC_ADD_RSA_IDENTITY()
    {
      Assert.Inconclusive(cTestNotImplemented);
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY()
    {
      Agent agent = new TestAgent();

      /* test adding RSA key */

      BlobBuilder builder = new BlobBuilder();
      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)mRsaKey.GetPrivateKeyParameters();
      builder.AddStringBlob(mRsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(rsaParameters.Modulus);
      builder.AddBigIntBlob(rsaParameters.PublicExponent);
      builder.AddBigIntBlob(rsaParameters.Exponent);
      builder.AddBigIntBlob(rsaParameters.QInv);
      builder.AddBigIntBlob(rsaParameters.P);
      builder.AddBigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(mRsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      ISshKey returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.GetPublicKeyParameters(),
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(),
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(mRsaKey.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(mRsaKey.Comment));
      Assert.That(returnedKey.MD5Fingerprint, Is.EqualTo(mRsaKey.MD5Fingerprint));

      /* test adding DSA key */

      agent = new TestAgent();
      builder.Clear();
      DsaPublicKeyParameters dsaPublicParameters =
        (DsaPublicKeyParameters)mDsaKey.GetPublicKeyParameters();
      DsaPrivateKeyParameters dsaPrivateParameters =
        (DsaPrivateKeyParameters)mDsaKey.GetPrivateKeyParameters();
      builder.AddStringBlob(mDsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(dsaPublicParameters.Parameters.P);
      builder.AddBigIntBlob(dsaPublicParameters.Parameters.Q);
      builder.AddBigIntBlob(dsaPublicParameters.Parameters.G);
      builder.AddBigIntBlob(dsaPublicParameters.Y);
      builder.AddBigIntBlob(dsaPrivateParameters.X);
      builder.AddStringBlob(mDsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.GetPublicKeyParameters(),
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(),
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(mDsaKey.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(mDsaKey.Comment));
      Assert.That(returnedKey.MD5Fingerprint, Is.EqualTo(mDsaKey.MD5Fingerprint));

      /* test adding ECDSA keys */

      List<ISshKey> ecdsaKeysList = new List<ISshKey>();
      ecdsaKeysList.Add(mEcdsa256Key);
      ecdsaKeysList.Add(mEcdsa384Key);
      ecdsaKeysList.Add(mEcdsa521Key);
      foreach (ISshKey key in ecdsaKeysList) {
        agent = new TestAgent();
        builder.Clear();
        ECPublicKeyParameters ecdsaPublicParameters =
          (ECPublicKeyParameters)key.GetPublicKeyParameters();
        ECPrivateKeyParameters ecdsaPrivateParameters =
          (ECPrivateKeyParameters)key.GetPrivateKeyParameters();
        string ecdsaAlgorithm = key.Algorithm.GetIdentifierString();
        builder.AddStringBlob(ecdsaAlgorithm);
        ecdsaAlgorithm =
          ecdsaAlgorithm.Replace(PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_PREFIX,
          string.Empty);
        builder.AddStringBlob(ecdsaAlgorithm);
        builder.AddBlob(ecdsaPublicParameters.Q.GetEncoded());
        builder.AddBigIntBlob(ecdsaPrivateParameters.D);
        builder.AddStringBlob(key.Comment);
        builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
        PrepareMessage(builder);
        agent.AnswerMessage(mStream);
        RewindStream();
        header = mParser.ReadHeader();
        Assert.That(header.BlobLength, Is.EqualTo(1));
        Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
        returnedKey = agent.KeyList.First();
        Assert.That(returnedKey.GetPublicKeyParameters(),
                    Is.InstanceOf<ECPublicKeyParameters>());
        Assert.That(returnedKey.GetPrivateKeyParameters(),
                    Is.InstanceOf<ECPrivateKeyParameters>());
        Assert.That(returnedKey.Size, Is.EqualTo(key.Size));
        Assert.That(returnedKey.Comment, Is.EqualTo(key.Comment));
        Assert.That(returnedKey.MD5Fingerprint, Is.EqualTo(key.MD5Fingerprint));
        Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(0));
      }

      /* test adding key that already is in KeyList does not create duplicate */
      int startingCount = agent.KeyList.Count();
      Assert.That(startingCount, Is.Not.EqualTo(0));
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      Assert.That(agent.KeyList.Count(), Is.EqualTo(startingCount));

      /* test locked => failure */
      agent = new TestAgent();
      agent.Lock(new byte[0]);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.KeyList.Count, Is.EqualTo(0));
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_ADD_ID_CONSTRAINED()
    {
      /* most code is shared with SSH2_AGENTC_ADD_IDENTITY, so we just
       * need to test the differences */

      Agent.ConfirmUserPermissionDelegate confirmCallback =
        delegate(ISshKey key) { return true; };

      Agent agent = new TestAgent();

      /* test that no confirmation callback returns failure */

      BlobBuilder builder = new BlobBuilder();
      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)mRsaKey.GetPrivateKeyParameters();
      builder.AddStringBlob(mRsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(rsaParameters.Modulus);
      builder.AddBigIntBlob(rsaParameters.PublicExponent);
      builder.AddBigIntBlob(rsaParameters.Exponent);
      builder.AddBigIntBlob(rsaParameters.QInv);
      builder.AddBigIntBlob(rsaParameters.P);
      builder.AddBigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(mRsaKey.Comment);
      //save blob so far so we don't have to repeat later.
      byte[] commonBlob = builder.GetBlob();
      builder.AddByte((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

      /* test adding key with confirm constraint */

      agent = new TestAgent();
      agent.ConfirmUserPermissionCallback = confirmCallback;
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      ISshKey returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(1));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[0].Data, Is.Null);

      /* test adding key with lifetime constraint */

      agent = new TestAgent();
      builder.Clear();
      builder.AddBytes(commonBlob);
      builder.AddByte((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(1));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME));
      Assert.That(returnedKey.Constraints[0].Data.GetType(),
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME.GetDataType()));
      Assert.That(returnedKey.Constraints[0].Data, Is.EqualTo(10));

      /* test adding key with multiple constraints */

      agent = new TestAgent();
      agent.ConfirmUserPermissionCallback = confirmCallback;
      builder.Clear();
      builder.AddBytes(commonBlob);
      builder.AddByte((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.AddByte((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(2));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[0].Data, Is.Null);
      Assert.That(returnedKey.Constraints[1].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME));
      Assert.That(returnedKey.Constraints[1].Data, Is.EqualTo(10));

      /* test adding key with multiple constraints in different order */

      agent = new TestAgent();
      agent.ConfirmUserPermissionCallback = confirmCallback;
      builder.Clear();
      builder.AddBytes(commonBlob);
      builder.AddByte((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.AddByte((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.KeyList.First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(2));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME));
      Assert.That(returnedKey.Constraints[0].Data, Is.EqualTo(10));
      Assert.That(returnedKey.Constraints[1].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[1].Data, Is.Null);
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
          ssh2KeyList[i].GetPublicKeyBlob();
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
      BlobBuilder builder = new BlobBuilder();

      Agent agent = new TestAgent(mAllKeys);
      Agent.BlobHeader header;
      byte[] signatureBlob;
      BlobParser signatureParser;
      string algorithm;
      byte[] signature;
      ISigner signer;
      bool signatureOk;
      BigInteger r, s;
      DerSequence seq;

      /* test signatures */

      foreach (ISshKey key in mAllKeys.Where(key => key.Version == SshVersion.SSH2)) {
        builder.Clear();
        builder.AddBlob(key.GetPublicKeyBlob());
        builder.AddStringBlob(signatureData);
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
        algorithm = signatureParser.ReadString();
        Assert.That(algorithm, Is.EqualTo(key.Algorithm.GetIdentifierString()));
        signature = signatureParser.ReadBlob().Data;
        if (key.Algorithm == PublicKeyAlgorithm.SSH_RSA) {
          Assert.That(signature.Length == key.Size / 8);
        } else if (key.Algorithm == PublicKeyAlgorithm.SSH_DSS) {
          Assert.That(signature.Length, Is.EqualTo(40));
          r = new BigInteger(1, signature, 0, 20);
          s = new BigInteger(1, signature, 20, 20);
          seq = new DerSequence(new DerInteger(r), new DerInteger(s));
          signature = seq.GetDerEncoded();
        } else if (key.Algorithm == PublicKeyAlgorithm.ECDSA_SHA2_NISTP256 ||
          key.Algorithm == PublicKeyAlgorithm.ECDSA_SHA2_NISTP384 ||
          key.Algorithm == PublicKeyAlgorithm.ECDSA_SHA2_NISTP521) {
          Assert.That(signature.Length, Is.AtLeast(key.Size / 4 + 8));
          Assert.That(signature.Length, Is.AtMost(key.Size / 4 + 10));
          BlobParser parser = new BlobParser(signature);
          r = new BigInteger(parser.ReadBlob().Data);
          s = new BigInteger(parser.ReadBlob().Data);
          seq = new DerSequence(new DerInteger(r), new DerInteger(s));
          signature = seq.GetDerEncoded();
        }
        signer = key.GetSigner();
        signer.Init(false, key.GetPublicKeyParameters());
        signer.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
        signatureOk = signer.VerifySignature(signature);
        Assert.That(signatureOk, Is.True, "invalid signature");
        Assert.That(header.BlobLength, Is.EqualTo(mStream.Position - 4));
      }

      /* test DSA key old signature format */

      builder.Clear();
      builder.AddBlob(mDsaKey.GetPublicKeyBlob());
      builder.AddStringBlob(signatureData);
      builder.AddInt((uint)Agent.SignRequestFlags.SSH_AGENT_OLD_SIGNATURE);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.Message,
                  Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
      signatureBlob = mParser.ReadBlob().Data;
      signatureParser = new BlobParser(signatureBlob);
      signature = signatureParser.ReadBlob().Data;
      Assert.That(signature.Length == 40);
      r = new BigInteger(1, signature, 0, 20);
      s = new BigInteger(1, signature, 20, 20);
      seq = new DerSequence(new DerInteger(r), new DerInteger(s));
      signature = seq.GetDerEncoded();
      signer = mDsaKey.GetSigner();
      signer.Init(false, mDsaKey.GetPublicKeyParameters());
      signer.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
      signatureOk = signer.VerifySignature(signature);
      Assert.That(signatureOk, Is.True, "invalid signature");
      Assert.That(header.BlobLength, Is.EqualTo(mStream.Position - 4));

      /* test key not found */

      agent = new TestAgent();
      builder.Clear();
      builder.AddBlob(mDsaKey.GetPublicKeyBlob());
      builder.AddStringBlob(signatureData);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      Agent.BlobHeader header2 = mParser.ReadHeader();
      Assert.That(header2.BlobLength, Is.EqualTo(1));
      Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

      /* test confirm constraint */

      agent = new TestAgent();
      Agent.KeyConstraint testConstraint = new Agent.KeyConstraint();
      testConstraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;      
      SshKey testKey = mDsaKey.Clone();
      testKey.AddConstraint(testConstraint);
      agent.AddKey(testKey);
      bool confirmCallbackReturnValue = false;
      agent.ConfirmUserPermissionCallback = delegate(ISshKey aKey)
      {
        return confirmCallbackReturnValue;
      };
      builder.Clear();
      builder.AddBlob(mDsaKey.GetPublicKeyBlob());
      builder.AddStringBlob(signatureData);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header2 = mParser.ReadHeader();
      Assert.That(header2.BlobLength, Is.EqualTo(1));
      Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      confirmCallbackReturnValue = true;
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header2 = mParser.ReadHeader();
      Assert.That(header2.BlobLength, Is.Not.EqualTo(1));
      Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REMOVE_IDENTITY()
    {
      Agent agent = new TestAgent(mAllKeys);
      BlobBuilder builder = new BlobBuilder();

      /* test remove key returns success when key is removed */

      builder.AddBlob(mRsaKey.GetPublicKeyBlob());
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      Agent.BlobHeader header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      Assert.That(agent.KeyList.SequenceEqual(mAllKeys.Where(key => key != mRsaKey)));

      /* test remove key returns failure when key does not exist */

      int startCount = agent.KeyList.Count();
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.KeyList.Count(), Is.EqualTo(startCount));

      /* test returns failure when locked */

      agent.Lock(new byte[0]);
      startCount = agent.KeyList.Count();
      builder.AddBlob(mDsaKey.GetPublicKeyBlob());
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(mStream);
      RewindStream();
      header = mParser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.KeyList.Count(), Is.EqualTo(startCount));
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
      agent = new TestAgent();
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

    [Test()]
    public void TestOnKeyListChanged()
    {
      Agent agent = new TestAgent();

      /* test that key with lifetime constraint is automatically removed *
       * after lifetime expires */

      AsymmetricCipherKeyPair keyPair =
        new AsymmetricCipherKeyPair(mRsaKey.GetPublicKeyParameters(),
          mRsaKey.GetPrivateKeyParameters());
      ISshKey key = new SshKey(SshVersion.SSH2, keyPair);
      Agent.KeyConstraint constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
      constraint.Data = (UInt32)1;
      key.AddConstraint(constraint);
      agent.AddKey(key);
      Thread.Sleep(500);
      Assert.That(agent.KeyList.Count, Is.EqualTo(1));
      Thread.Sleep(1000);
      Assert.That(agent.KeyList.Count, Is.EqualTo(0));
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
      builder.AddStringBlob(aPassword);
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
