//
// AgentTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013,2015,2017 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


// Agent protocol is specified at http://api.libssh.org/rfc/PROTOCOL.agent
// Certificates are specified at http://api.libssh.org/rfc/PROTOCOL.certkeys

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using dlech.SshAgentLib;
using dlech.SshAgentLib.Crypto;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLibTests
{
  /// <summary>
  ///This is a test class for Agent class and is intended
  ///to contain all Agent Unit Tests
  ///</summary>
  [TestFixture]
  public class AgentTest
  {
    private const string cTestNotImplemented = "Test not implemented";

    /* instance variables */
    static byte[] buffer;
    static MemoryStream stream;
    static BlobParser parser;
    static SshKey rsa1Key;
    static SshKey rsaKey;
    static SshKey dsaKey;
    static SshKey ecdsa256Key;
    static SshKey ecdsa384Key;
    static SshKey ecdsa521Key;
    static SshKey ed25519Key;
    static ReadOnlyCollection<ISshKey> allKeys;


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
      buffer = new byte[4096];
      stream = new MemoryStream(buffer);
      parser = new BlobParser(stream);

      rsa1Key = KeyGenerator.CreateKey(SshVersion.SSH1,
        PublicKeyAlgorithm.SSH_RSA, "SSH1 RSA test key");
      rsaKey = KeyGenerator.CreateKey(SshVersion.SSH2,
        PublicKeyAlgorithm.SSH_RSA, "SSH2 RSA test key");
      dsaKey = KeyGenerator.CreateKey(SshVersion.SSH2,
        PublicKeyAlgorithm.SSH_DSS, "SSH2 DSA test key");
      ecdsa256Key = KeyGenerator.CreateKey(SshVersion.SSH2,
        PublicKeyAlgorithm.ECDSA_SHA2_NISTP256, "SSH2 ECDSA 256 test key");
      ecdsa384Key = KeyGenerator.CreateKey(SshVersion.SSH2,
       PublicKeyAlgorithm.ECDSA_SHA2_NISTP384, "SSH2 ECDSA 384 test key");
      ecdsa521Key = KeyGenerator.CreateKey(SshVersion.SSH2,
       PublicKeyAlgorithm.ECDSA_SHA2_NISTP521, "SSH2 ECDSA 521 test key");
      ed25519Key = KeyGenerator.CreateKey(SshVersion.SSH2,
        PublicKeyAlgorithm.ED25519, "SSH2 ED25519 test key");

      List<ISshKey> allKeysList = new List<ISshKey>();
      allKeysList.Add(rsa1Key);
      allKeysList.Add(rsaKey);
      allKeysList.Add(dsaKey);
      allKeysList.Add(ecdsa256Key);
      allKeysList.Add(ecdsa384Key);
      allKeysList.Add(ecdsa521Key);
      allKeysList.Add(ed25519Key);
      allKeys = allKeysList.AsReadOnly();
    }

    [Test()]
    public void TestAnswerUnknownRequest()
    {
      Agent agent = new TestAgent();

      var unknownMessage = (byte)Agent.Message.UNKNOWN;
      Assert.That(unknownMessage, Is.Not.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      PrepareSimpleMessage(unchecked((Agent.Message)(unknownMessage)));
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
    }

    [Test]
    public void TestAnswerSSH1_AGENTC_ADD_RSA_IDENTITY()
    {
      Agent agent = new TestAgent();
      BlobBuilder builder = new BlobBuilder();

      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)rsa1Key.GetPrivateKeyParameters();
      builder.AddInt(rsa1Key.Size);
      builder.AddSsh1BigIntBlob(rsaParameters.Modulus);
      builder.AddSsh1BigIntBlob(rsaParameters.PublicExponent);
      builder.AddSsh1BigIntBlob(rsaParameters.Exponent);
      builder.AddSsh1BigIntBlob(rsaParameters.QInv);
      builder.AddSsh1BigIntBlob(rsaParameters.P);
      builder.AddSsh1BigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(rsa1Key.Comment);
      builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      ISshKey returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.GetPublicKeyParameters(),
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(),
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(rsa1Key.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(rsa1Key.Comment));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(rsa1Key.GetMD5Fingerprint()));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_RSA()
    {
      Agent agent = new TestAgent();
      BlobBuilder builder = new BlobBuilder();

      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();
      builder.AddStringBlob(rsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(rsaParameters.Modulus);
      builder.AddBigIntBlob(rsaParameters.PublicExponent);
      builder.AddBigIntBlob(rsaParameters.Exponent);
      builder.AddBigIntBlob(rsaParameters.QInv);
      builder.AddBigIntBlob(rsaParameters.P);
      builder.AddBigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(rsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.GetPublicKeyParameters(),
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(),
                  Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(rsaKey.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(rsaKey.Comment));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(rsaKey.GetMD5Fingerprint()));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_RsaCert()
    {
      var rsaParameters = (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();

      var certBuilder = new BlobBuilder();
      certBuilder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_RSA_CERT_V1);
      certBuilder.AddBlob(new byte[32]); // nonce
      certBuilder.AddBigIntBlob(rsaParameters.PublicExponent); // e
      certBuilder.AddBigIntBlob(rsaParameters.Modulus); // n
      certBuilder.AddUInt64(0); // serial
      certBuilder.AddUInt32((uint)Ssh2CertType.User); // type
      certBuilder.AddStringBlob("rsa-test-cert"); // key id
      certBuilder.AddBlob(new byte[0]); // valid principals
      certBuilder.AddUInt64(0); // valid after
      certBuilder.AddUInt64(ulong.MaxValue); // valid before
      certBuilder.AddBlob(new byte[0]); //critical options
      certBuilder.AddBlob(new byte[0]); // extensions
      certBuilder.AddBlob(new byte[0]); // reserved
      certBuilder.AddBlob(rsaKey.GetPublicKeyBlob()); // signature key
      certBuilder.AddBlob(new byte[0]); // signature

      var builder = new BlobBuilder();
      builder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_RSA_CERT_V1);
      builder.AddBlob(certBuilder.GetBlob());
      builder.AddBigIntBlob(rsaParameters.Exponent); // D
      builder.AddBigIntBlob(rsaParameters.QInv);
      builder.AddBigIntBlob(rsaParameters.P);
      builder.AddBigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(rsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

      PrepareMessage(builder);
      var agent = new TestAgent();
      agent.AnswerMessage(stream);

      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().Single();
      Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<RsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(rsaKey.Size));
      Assert.That(returnedKey.Certificate.Blob, Is.EqualTo(certBuilder.GetBlob()));
      Assert.That(returnedKey.Comment, Is.EqualTo(rsaKey.Comment));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(rsaKey.GetMD5Fingerprint()));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_DSA()
    {
      DsaPublicKeyParameters dsaPublicParameters =
        (DsaPublicKeyParameters)dsaKey.GetPublicKeyParameters();
      DsaPrivateKeyParameters dsaPrivateParameters =
        (DsaPrivateKeyParameters)dsaKey.GetPrivateKeyParameters();
      
      var builder = new BlobBuilder();
      builder.AddStringBlob(dsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(dsaPublicParameters.Parameters.P);
      builder.AddBigIntBlob(dsaPublicParameters.Parameters.Q);
      builder.AddBigIntBlob(dsaPublicParameters.Parameters.G);
      builder.AddBigIntBlob(dsaPublicParameters.Y);
      builder.AddBigIntBlob(dsaPrivateParameters.X);
      builder.AddStringBlob(dsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

      PrepareMessage(builder);
      var agent = new TestAgent();
      agent.AnswerMessage(stream);
      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.GetPublicKeyParameters(),
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(),
                  Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(dsaKey.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(dsaKey.Comment));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(dsaKey.GetMD5Fingerprint()));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_DsaCert()
    {
      var dsaPublicParameters = (DsaPublicKeyParameters)dsaKey.GetPublicKeyParameters();
      var dsaPrivateParameters = (DsaPrivateKeyParameters)dsaKey.GetPrivateKeyParameters();
      
      var certBuilder = new BlobBuilder();
      certBuilder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_DSA_CERT_V1);
      certBuilder.AddBlob(new byte[32]); // nonce
      certBuilder.AddBigIntBlob(dsaPublicParameters.Parameters.P); // p
      certBuilder.AddBigIntBlob(dsaPublicParameters.Parameters.Q); // q
      certBuilder.AddBigIntBlob(dsaPublicParameters.Parameters.G); // g
      certBuilder.AddBigIntBlob(dsaPublicParameters.Y); // y
      certBuilder.AddUInt64(0); // serial
      certBuilder.AddUInt32((uint)Ssh2CertType.User); // type
      certBuilder.AddStringBlob("dsa-test-cert"); // key id
      certBuilder.AddBlob(new byte[0]); // valid principals
      certBuilder.AddUInt64(0); // valid after
      certBuilder.AddUInt64(ulong.MaxValue); // valid before
      certBuilder.AddBlob(new byte[0]); //critical options
      certBuilder.AddBlob(new byte[0]); // extensions
      certBuilder.AddBlob(new byte[0]); // reserved
      certBuilder.AddBlob(dsaKey.GetPublicKeyBlob()); // signature key
      certBuilder.AddBlob(new byte[0]); // signature

      var builder = new BlobBuilder();
      builder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_DSA_CERT_V1);
      builder.AddBlob(certBuilder.GetBlob());
      builder.AddBigIntBlob(dsaPrivateParameters.X);
      builder.AddStringBlob(dsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

      PrepareMessage(builder);
      var agent = new TestAgent();
      agent.AnswerMessage(stream);

      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().Single();
      Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<DsaKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(dsaKey.Size));
      Assert.That(returnedKey.Certificate.Blob, Is.EqualTo(certBuilder.GetBlob()));
      Assert.That(returnedKey.Comment, Is.EqualTo(dsaKey.Comment));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(dsaKey.GetMD5Fingerprint()));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_ECDSA()
    {
      var agent = new TestAgent();
      var builder = new BlobBuilder();

      List<ISshKey> ecdsaKeysList = new List<ISshKey>();
      ecdsaKeysList.Add(ecdsa256Key);
      ecdsaKeysList.Add(ecdsa384Key);
      ecdsaKeysList.Add(ecdsa521Key);
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
        agent.AnswerMessage(stream);
        RewindStream();
        var header = parser.ReadHeader();
        Assert.That(header.BlobLength, Is.EqualTo(1));
        Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
        var returnedKey = agent.GetAllKeys().First();
        Assert.That(returnedKey.GetPublicKeyParameters(),
                    Is.InstanceOf<ECPublicKeyParameters>());
        Assert.That(returnedKey.GetPrivateKeyParameters(),
                    Is.InstanceOf<ECPrivateKeyParameters>());
        Assert.That(returnedKey.Size, Is.EqualTo(key.Size));
        Assert.That(returnedKey.Comment, Is.EqualTo(key.Comment));
        Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(key.GetMD5Fingerprint()));
        Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(0));
      }
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_EcdsaCert()
    {
      var ecdsaPublicParameters = (ECPublicKeyParameters)ecdsa256Key.GetPublicKeyParameters();
      var ecdsaPrivateParameters = (ECPrivateKeyParameters)ecdsa256Key.GetPrivateKeyParameters();
      
      var certBuilder = new BlobBuilder();
      certBuilder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_CERT_V1);
      certBuilder.AddBlob(new byte[32]); // nonce
      certBuilder.AddStringBlob(PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP256); // curve
      certBuilder.AddBlob(ecdsaPublicParameters.Q.GetEncoded()); // public key
      certBuilder.AddUInt64(0); // serial
      certBuilder.AddUInt32((uint)Ssh2CertType.User); // type
      certBuilder.AddStringBlob("ecdsa-test-cert"); // key id
      certBuilder.AddBlob(new byte[0]); // valid principals
      certBuilder.AddUInt64(0); // valid after
      certBuilder.AddUInt64(ulong.MaxValue); // valid before
      certBuilder.AddBlob(new byte[0]); //critical options
      certBuilder.AddBlob(new byte[0]); // extensions
      certBuilder.AddBlob(new byte[0]); // reserved
      certBuilder.AddBlob(dsaKey.GetPublicKeyBlob()); // signature key
      certBuilder.AddBlob(new byte[0]); // signature

      var builder = new BlobBuilder();
      builder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_CERT_V1);
      builder.AddBlob(certBuilder.GetBlob());
      builder.AddBigIntBlob(ecdsaPrivateParameters.D);
      builder.AddStringBlob(ecdsa256Key.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

      PrepareMessage(builder);
      var agent = new TestAgent();
      agent.AnswerMessage(stream);

      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<ECPublicKeyParameters>());
      Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<ECPrivateKeyParameters>());
      Assert.That(returnedKey.Size, Is.EqualTo(ecdsa256Key.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(ecdsa256Key.Comment));
      Assert.That(returnedKey.Certificate.Blob, Is.EqualTo(certBuilder.GetBlob()));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(ecdsa256Key.GetMD5Fingerprint()));
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(0));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_Ed25519()
    {
      var publicKeyParams = (Ed25519PublicKeyParameter)ed25519Key.GetPublicKeyParameters();
      var privateKeyParams = (Ed25519PrivateKeyParameter)ed25519Key.GetPrivateKeyParameters();

      var builder = new BlobBuilder();
      builder.AddStringBlob(ed25519Key.Algorithm.GetIdentifierString());
      builder.AddBlob(publicKeyParams.Key);
      builder.AddBlob(privateKeyParams.Signature);
      builder.AddStringBlob(ed25519Key.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

      PrepareMessage(builder);
      var agent = new TestAgent();
      agent.AnswerMessage(stream);

      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<Ed25519PublicKeyParameter>());
      Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<Ed25519PrivateKeyParameter>());
      Assert.That(returnedKey.Size, Is.EqualTo(ed25519Key.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(ed25519Key.Comment));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(ed25519Key.GetMD5Fingerprint()));
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(0));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_Ed25519Cert()
    {
      var publicKeyParams = (Ed25519PublicKeyParameter)ed25519Key.GetPublicKeyParameters();
      var privateKeyParams = (Ed25519PrivateKeyParameter)ed25519Key.GetPrivateKeyParameters();

      var certBuilder = new BlobBuilder();
      certBuilder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_ED25519_CERT_V1);
      certBuilder.AddBlob(new byte[32]); // nonce
      certBuilder.AddBlob(publicKeyParams.Key); // public key
      certBuilder.AddUInt64(0); // serial
      certBuilder.AddUInt32((uint)Ssh2CertType.User); // type
      certBuilder.AddStringBlob("ed25519-test-cert"); // key id
      certBuilder.AddBlob(new byte[0]); // valid principals
      certBuilder.AddUInt64(0); // valid after
      certBuilder.AddUInt64(ulong.MaxValue); // valid before
      certBuilder.AddBlob(new byte[0]); //critical options
      certBuilder.AddBlob(new byte[0]); // extensions
      certBuilder.AddBlob(new byte[0]); // reserved
      certBuilder.AddBlob(ed25519Key.GetPublicKeyBlob()); // signature key
      certBuilder.AddBlob(new byte[0]); // signature

      var builder = new BlobBuilder();
      builder.AddStringBlob(PublicKeyAlgorithmExt.ALGORITHM_ED25519_CERT_V1);
      builder.AddBlob(certBuilder.GetBlob());
      builder.AddBlob(publicKeyParams.Key);
      builder.AddBlob(privateKeyParams.Signature);
      builder.AddStringBlob(ed25519Key.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);

      PrepareMessage(builder);
      var agent = new TestAgent();
      agent.AnswerMessage(stream);

      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      var returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.GetPublicKeyParameters(), Is.InstanceOf<Ed25519PublicKeyParameter>());
      Assert.That(returnedKey.GetPrivateKeyParameters(), Is.InstanceOf<Ed25519PrivateKeyParameter>());
      Assert.That(returnedKey.Size, Is.EqualTo(ed25519Key.Size));
      Assert.That(returnedKey.Comment, Is.EqualTo(ed25519Key.Comment));
      Assert.That(returnedKey.Certificate.Blob, Is.EqualTo(certBuilder.GetBlob()));
      Assert.That(returnedKey.GetMD5Fingerprint(), Is.EqualTo(ed25519Key.GetMD5Fingerprint()));
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(0));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_NoDuplicates()
    {
      var agent = new TestAgent();
      var builder = new BlobBuilder();

      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();
      builder.AddStringBlob(rsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(rsaParameters.Modulus);
      builder.AddBigIntBlob(rsaParameters.PublicExponent);
      builder.AddBigIntBlob(rsaParameters.Exponent);
      builder.AddBigIntBlob(rsaParameters.QInv);
      builder.AddBigIntBlob(rsaParameters.P);
      builder.AddBigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(rsaKey.Comment);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);

      /* test adding key that already is in KeyList does not create duplicate */
      int startingCount = agent.GetAllKeys().Count();
      Assume.That(startingCount, Is.Not.EqualTo(0));
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      Assert.That(agent.GetAllKeys().Count(), Is.EqualTo(startingCount));
    }

    [Test]
    public void TestAnswerSSH2_AGENTC_ADD_IDENTITY_WhileLocked()
    {
      var agent = new TestAgent();
      var builder = new BlobBuilder();

      /* test locked => failure */
      agent.Lock(new byte[0]);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      var header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.GetAllKeys().Count, Is.EqualTo(0));
    }
    
    [Test()]
    public void TestAnswerSSH1_AGENTC_ADD_RSA_ID_CONSTRAINED()
    {
      /* most code is shared with SSH1_AGENTC_ADD_RSA_IDENTITY, so we just
       * need to test the differences */

      Agent.ConfirmUserPermissionDelegate confirmCallback =
        delegate(ISshKey k, Process p) { return true; };

      Agent agent = new TestAgent();

      /* test that no confirmation callback returns failure */

      BlobBuilder builder = new BlobBuilder();
      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)rsa1Key.GetPrivateKeyParameters();
      builder.AddInt(rsa1Key.Size);
      builder.AddSsh1BigIntBlob(rsaParameters.Modulus);
      builder.AddSsh1BigIntBlob(rsaParameters.PublicExponent);
      builder.AddSsh1BigIntBlob(rsaParameters.Exponent);
      builder.AddSsh1BigIntBlob(rsaParameters.QInv);
      builder.AddSsh1BigIntBlob(rsaParameters.P);
      builder.AddSsh1BigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(rsa1Key.Comment);
      //save blob so far so we don't have to repeat later.
      byte[] commonBlob = builder.GetBlob();
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

      /* test adding key with confirm constraint */

      agent = new TestAgent();
      agent.ConfirmUserPermissionCallback = confirmCallback;
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      ISshKey returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(1));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[0].Data, Is.Null);

      /* test adding key with lifetime constraint */

      agent = new TestAgent();
      builder.Clear();
      builder.AddBytes(commonBlob);
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.GetAllKeys().First();
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
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.GetAllKeys().First();
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
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(2));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME));
      Assert.That(returnedKey.Constraints[0].Data, Is.EqualTo(10));
      Assert.That(returnedKey.Constraints[1].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[1].Data, Is.Null);
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_ADD_ID_CONSTRAINED()
    {
      /* most code is shared with SSH2_AGENTC_ADD_IDENTITY, so we just
       * need to test the differences */

      Agent.ConfirmUserPermissionDelegate confirmCallback =
        delegate(ISshKey k, Process p) { return true; };

      Agent agent = new TestAgent();

      /* test that no confirmation callback returns failure */

      BlobBuilder builder = new BlobBuilder();
      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)rsaKey.GetPrivateKeyParameters();
      builder.AddStringBlob(rsaKey.Algorithm.GetIdentifierString());
      builder.AddBigIntBlob(rsaParameters.Modulus);
      builder.AddBigIntBlob(rsaParameters.PublicExponent);
      builder.AddBigIntBlob(rsaParameters.Exponent);
      builder.AddBigIntBlob(rsaParameters.QInv);
      builder.AddBigIntBlob(rsaParameters.P);
      builder.AddBigIntBlob(rsaParameters.Q);
      builder.AddStringBlob(rsaKey.Comment);
      //save blob so far so we don't have to repeat later.
      byte[] commonBlob = builder.GetBlob();
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

      /* test adding key with confirm constraint */

      agent = new TestAgent();
      agent.ConfirmUserPermissionCallback = confirmCallback;
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      ISshKey returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(1));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[0].Data, Is.Null);

      /* test adding key with lifetime constraint */

      agent = new TestAgent();
      builder.Clear();
      builder.AddBytes(commonBlob);
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.GetAllKeys().First();
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
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.GetAllKeys().First();
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
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      builder.AddInt(10);
      builder.AddUInt8((byte)Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      returnedKey = agent.GetAllKeys().First();
      Assert.That(returnedKey.Constraints.Count(), Is.EqualTo(2));
      Assert.That(returnedKey.Constraints[0].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME));
      Assert.That(returnedKey.Constraints[0].Data, Is.EqualTo(10));
      Assert.That(returnedKey.Constraints[1].Type,
        Is.EqualTo(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM));
      Assert.That(returnedKey.Constraints[1].Data, Is.Null);
    }

    [Test()]
    public void TestAnswerSSH1_AGENTC_REQUEST_RSA_IDENTITIES()
    {
      Agent agent = new TestAgent(allKeys);

      /* send request for SSH1 identities */
      PrepareSimpleMessage(Agent.Message.SSH1_AGENTC_REQUEST_RSA_IDENTITIES);
      agent.AnswerMessage(stream);
      RewindStream();

      /* check that we received proper response type */
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.Message,
        Is.EqualTo(Agent.Message.SSH1_AGENT_RSA_IDENTITIES_ANSWER));

      /* check that we received the correct key count */
      UInt32 actualKeyCount = parser.ReadUInt32();
      List<ISshKey> ssh1KeyList =
        agent.GetAllKeys().Where(key => key.Version == SshVersion.SSH1).ToList();
      int expectedSsh1KeyCount = ssh1KeyList.Count;
      Assert.That(actualKeyCount, Is.EqualTo(expectedSsh1KeyCount));

      /* check that we have data for each key */
      for (int i = 0; i < actualKeyCount; i++) {
        uint actualKeySizeBlob = parser.ReadUInt32();
        BigInteger actualExponentBlob = new BigInteger(1, parser.ReadSsh1BigIntBlob());
        BigInteger actualModulusBlob = new BigInteger(1, parser.ReadSsh1BigIntBlob());

        Assert.That(actualKeySizeBlob, Is.EqualTo(ssh1KeyList[i].Size));
        Assert.That(actualModulusBlob, Is.EqualTo((ssh1KeyList[i].GetPublicKeyParameters() as RsaKeyParameters).Modulus));
        Assert.That(actualExponentBlob, Is.EqualTo((ssh1KeyList[i].GetPublicKeyParameters() as RsaKeyParameters).Exponent));

        string actualComment = parser.ReadString();
        string expectedComment = ssh1KeyList[i].Comment;
        Assert.That(actualComment, Is.EqualTo(expectedComment));
      }
      /* verify that the overall response length is correct */
      Assert.That(header.BlobLength, Is.EqualTo(stream.Position - 4));
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REQUEST_IDENTITIES()
    {
      Agent agent = new TestAgent(allKeys);

      /* send request for SSH2 identities */
      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REQUEST_IDENTITIES);
      agent.AnswerMessage(stream);
      RewindStream();

      /* check that we received proper response type */
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.Message,
        Is.EqualTo(Agent.Message.SSH2_AGENT_IDENTITIES_ANSWER));

      /* check that we received the correct key count */
      UInt32 actualKeyCount = parser.ReadUInt32();
      List<ISshKey> ssh2KeyList =
        agent.GetAllKeys().Where(key => key.Version == SshVersion.SSH2).ToList();
      int expectedSsh2KeyCount = ssh2KeyList.Count;
      Assert.That(actualKeyCount, Is.EqualTo(expectedSsh2KeyCount));

      /* check that we have data for each key */
      for (int i = 0; i < actualKeyCount; i++) {
        byte[] actualPublicKeyBlob = parser.ReadBlob();
        byte[] expectedPublicKeyBlob =
          ssh2KeyList[i].GetPublicKeyBlob();
        Assert.That(actualPublicKeyBlob, Is.EqualTo(expectedPublicKeyBlob));
        string actualComment = parser.ReadString();
        string expectedComment = ssh2KeyList[i].Comment;
        Assert.That(actualComment, Is.EqualTo(expectedComment));
      }
      /* verify that the overall response length is correct */
      Assert.That(header.BlobLength, Is.EqualTo(stream.Position - 4));
    }

    [Test()]
    public void TestAnswerSSH1_AGENTC_RSA_CHALLENGE()
    {
      Agent agent = new TestAgent(allKeys);

      /* test answering to RSA challenge */

      BlobBuilder builder = new BlobBuilder();
      RsaPrivateCrtKeyParameters rsaParameters =
        (RsaPrivateCrtKeyParameters)rsa1Key.GetPrivateKeyParameters();
      builder.AddInt(rsa1Key.Size);
      builder.AddSsh1BigIntBlob(rsaParameters.PublicExponent);
      builder.AddSsh1BigIntBlob(rsaParameters.Modulus);

      byte[] decryptedChallenge = new byte[8];
      byte[] sessionId  = new byte[16];

      Random random = new Random();
      random.NextBytes(decryptedChallenge);
      random.NextBytes(sessionId);

      IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
      engine.Init(true, rsa1Key.GetPublicKeyParameters());

      byte[] encryptedChallenge = engine.ProcessBlock(decryptedChallenge, 0,
        decryptedChallenge.Length);

      BigInteger chal = new BigInteger(encryptedChallenge);
      builder.AddSsh1BigIntBlob(chal);
      builder.AddBytes(sessionId);
      builder.AddInt(1);

      builder.InsertHeader(Agent.Message.SSH1_AGENTC_RSA_CHALLENGE);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      byte[] md5Received = parser.ReadBytes(16);

      /* check that proper response type was received */
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH1_AGENT_RSA_RESPONSE));

      using (MD5 md5 = MD5.Create())
      {
        byte[] md5Buffer = new byte[48];
        decryptedChallenge.CopyTo(md5Buffer, 0);
        sessionId.CopyTo(md5Buffer, 32);

        byte[] md5Expected = md5.ComputeHash(md5Buffer);

        /* check the encrypted challenge was successfully read */
        Assert.That(md5Received, Is.EqualTo(md5Expected));
      }

    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_SIGN_REQUEST()
    {
      const string signatureData = "this is the data that gets signed";
      byte[] signatureDataBytes = Encoding.UTF8.GetBytes(signatureData);
      BlobBuilder builder = new BlobBuilder();

      Agent agent = new TestAgent(allKeys);
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

      foreach (ISshKey key in allKeys.Where(key => key.Version == SshVersion.SSH2)) {
        builder.Clear();
        builder.AddBlob(key.GetPublicKeyBlob());
        builder.AddStringBlob(signatureData);
        builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
        PrepareMessage(builder);
        agent.AnswerMessage(stream);
        RewindStream();

        /* check that proper response type was received */
        header = parser.ReadHeader();
        Assert.That(header.Message,
                    Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
        signatureBlob = parser.ReadBlob();
        signatureParser = new BlobParser(signatureBlob);
        algorithm = signatureParser.ReadString();
        Assert.That(algorithm, Is.EqualTo(key.Algorithm.GetIdentifierString()));
        signature = signatureParser.ReadBlob();
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
          BlobParser sigParser = new BlobParser(signature);
          r = new BigInteger(sigParser.ReadBlob());
          s = new BigInteger(sigParser.ReadBlob());
          seq = new DerSequence(new DerInteger(r), new DerInteger(s));
          signature = seq.GetDerEncoded();
        } else if (key.Algorithm == PublicKeyAlgorithm.ED25519) {
            Assert.That(signature.Length, Is.EqualTo(64));
        }
        signer = key.GetSigner();
        signer.Init(false, key.GetPublicKeyParameters());
        signer.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
        signatureOk = signer.VerifySignature(signature);
        Assert.That(signatureOk, Is.True, "invalid signature");
        Assert.That(header.BlobLength, Is.EqualTo(stream.Position - 4));
      }

      /* test DSA key old signature format */

      builder.Clear();
      builder.AddBlob(dsaKey.GetPublicKeyBlob());
      builder.AddStringBlob(signatureData);
      builder.AddUInt32((uint)Agent.SignRequestFlags.SSH_AGENT_OLD_SIGNATURE);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.Message,
                  Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
      signatureBlob = parser.ReadBlob();
      signatureParser = new BlobParser(signatureBlob);
      signature = signatureParser.ReadBlob();
      Assert.That(signature.Length == 40);
      r = new BigInteger(1, signature, 0, 20);
      s = new BigInteger(1, signature, 20, 20);
      seq = new DerSequence(new DerInteger(r), new DerInteger(s));
      signature = seq.GetDerEncoded();
      signer = dsaKey.GetSigner();
      signer.Init(false, dsaKey.GetPublicKeyParameters());
      signer.BlockUpdate(signatureDataBytes, 0, signatureDataBytes.Length);
      signatureOk = signer.VerifySignature(signature);
      Assert.That(signatureOk, Is.True, "invalid signature");
      Assert.That(header.BlobLength, Is.EqualTo(stream.Position - 4));

      /* test key not found */

      agent = new TestAgent();
      builder.Clear();
      builder.AddBlob(dsaKey.GetPublicKeyBlob());
      builder.AddStringBlob(signatureData);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header2 = parser.ReadHeader();
      Assert.That(header2.BlobLength, Is.EqualTo(1));
      Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));

      /* test confirm constraint */

      agent = new TestAgent();
      Agent.KeyConstraint testConstraint = new Agent.KeyConstraint();
      testConstraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
      SshKey testKey = dsaKey.Clone();
      bool confirmCallbackReturnValue = false;
      agent.ConfirmUserPermissionCallback = delegate(ISshKey k, Process p)
      {
        return confirmCallbackReturnValue;
      };
      testKey.AddConstraint(testConstraint);
      agent.AddKey(testKey);
      builder.Clear();
      builder.AddBlob(dsaKey.GetPublicKeyBlob());
      builder.AddStringBlob(signatureData);
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header2 = parser.ReadHeader();
      Assert.That(header2.BlobLength, Is.EqualTo(1));
      Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      confirmCallbackReturnValue = true;
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header2 = parser.ReadHeader();
      Assert.That(header2.BlobLength, Is.Not.EqualTo(1));
      Assert.That(header2.Message, Is.EqualTo(Agent.Message.SSH2_AGENT_SIGN_RESPONSE));
    }

    [Test()]
    public void TestAnswerSSH1_AGENTC_REMOVE_RSA_IDENTITY()
    {
      Agent agent = new TestAgent(allKeys);
      BlobBuilder builder = new BlobBuilder();

      /* test remove key returns success when key is removed */

      builder.AddBytes(rsa1Key.GetPublicKeyBlob());
      builder.InsertHeader(Agent.Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      Assert.That(agent.GetAllKeys()
        .SequenceEqual(allKeys.Where(key => key != rsa1Key)));

      /* test remove key returns failure when key does not exist */

      int startCount = agent.GetAllKeys().Count();
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.GetAllKeys().Count(), Is.EqualTo(startCount));

      /* test returns failure when locked */

      agent.Lock(new byte[0]);
      startCount = agent.GetAllKeys().Count();
      builder.AddBlob(dsaKey.GetPublicKeyBlob());
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.GetAllKeys().Count(), Is.EqualTo(startCount));
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REMOVE_IDENTITY()
    {
      Agent agent = new TestAgent(allKeys);
      BlobBuilder builder = new BlobBuilder();

      /* test remove key returns success when key is removed */

      builder.AddBlob(rsaKey.GetPublicKeyBlob());
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      Assert.That(agent.GetAllKeys()
        .SequenceEqual(allKeys.Where(key => key != rsaKey)));

      /* test remove key returns failure when key does not exist */

      int startCount = agent.GetAllKeys().Count();
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.GetAllKeys().Count(), Is.EqualTo(startCount));

      /* test returns failure when locked */

      agent.Lock(new byte[0]);
      startCount = agent.GetAllKeys().Count();
      builder.AddBlob(dsaKey.GetPublicKeyBlob());
      builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
      PrepareMessage(builder);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE));
      Assert.That(agent.GetAllKeys().Count(), Is.EqualTo(startCount));
    }

    [Test()]
    public void TestAnswerSSH2_AGENTC_REMOVE_ALL_IDENTITIES()
    {
      Agent agent = new TestAgent(allKeys);

      /* test that remove all keys removes keys */

      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
      agent.AnswerMessage(stream);
      RewindStream();
      Agent.BlobHeader header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));
      int actualKeyCount = agent.GetAllKeys()
        .Count(key => key.Version != SshVersion.SSH2);
      int expectedKeyCount = allKeys.Count(key => key.Version != SshVersion.SSH2);
      Assert.That(actualKeyCount, Is.EqualTo(expectedKeyCount));

      /* test that remove all keys returns success even when there are no keys */
      agent = new TestAgent();
      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
      Assert.That(header.BlobLength, Is.EqualTo(1));
      Assert.That(header.Message, Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS));

      /* test that returns failure when locked */
      agent.Lock(new byte[0]);
      PrepareSimpleMessage(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
      agent.AnswerMessage(stream);
      RewindStream();
      header = parser.ReadHeader();
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

      Agent.LockEventHandler agentLocked = (s, e) =>
        {
          Assert.That(agentLockedCalled, Is.False,
            "LockEvent fired without resetting agentLockedCalled");
          agentLockedCalled = true;
        };

      agent.Locked += new Agent.LockEventHandler(agentLocked);


      /* test that unlock does nothing when already unlocked */

      PrepareLockMessage(false, password);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      RewindStream();
      replyHeader = parser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because agent was already unlocked");
      Assert.That(agent.IsLocked, Is.False, "Agent should still be unlocked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that locking works */

      PrepareLockMessage(true, password);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      RewindStream();
      replyHeader = parser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_SUCCESS),
        "Locking should have succeeded");
      Assert.That(agent.IsLocked, Is.True, "Agent should be locked");
      Assert.That(agentLockedCalled, Is.True,
        "agentLocked should have been called");


      /* test that trying to lock when already locked fails */

      PrepareLockMessage(true, password);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      RewindStream();
      replyHeader = parser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because agent was already unlocked");
      Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that unlocking with wrong password fails */

      PrepareLockMessage(false, password + "x");
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      RewindStream();
      replyHeader = parser.ReadHeader();
      Assert.That(replyHeader.Message,
        Is.EqualTo(Agent.Message.SSH_AGENT_FAILURE),
        "Unlock should have failed because password was incorrect");
      Assert.That(agent.IsLocked, Is.True, "Agent should still be locked");
      Assert.That(agentLockedCalled, Is.False,
        "agentLocked should not have been called because state did not change.");

      /* test that unlocking works */

      PrepareLockMessage(false, password);
      agentLockedCalled = false;
      agent.AnswerMessage(stream);
      RewindStream();
      replyHeader = parser.ReadHeader();
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
        new AsymmetricCipherKeyPair(rsaKey.GetPublicKeyParameters(),
          rsaKey.GetPrivateKeyParameters());
      ISshKey key = new SshKey(SshVersion.SSH2, keyPair);
      Agent.KeyConstraint constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
      constraint.Data = (UInt32)1;
      key.AddConstraint(constraint);
      agent.AddKey(key);
      Thread.Sleep(500);
      Assert.That(agent.GetAllKeys().Count, Is.EqualTo(1));
      Thread.Sleep(1000);
      Assert.That(agent.GetAllKeys().Count, Is.EqualTo(0));
    }

    #region helper methods

    /// <summary>
    /// writes BlobBuilder data to beginning of Stream and resets Stream
    /// </summary>
    private void PrepareMessage(BlobBuilder aBuilder)
    {
      ResetStream();
      stream.WriteBlob(aBuilder);
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
      Array.Clear(buffer, 0, buffer.Length);
      RewindStream();
    }

    private void RewindStream()
    {
      stream.Position = 0;
    }
  }

    #endregion
}
