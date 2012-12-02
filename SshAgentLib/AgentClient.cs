using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;

namespace dlech.SshAgentLib
{
  public abstract class AgentClient : IAgent
  {
    private const string cUnsupportedSshVersion = "Unsupported SSH version";

    public abstract void SendMessage(byte[] aMessage, out byte[] aReply);

    /// <summary>
    /// Adds key to SSH agent
    /// </summary>
    /// <param name="aKey">the key to add</param>
    /// <returns>true if operation was successful</returns>
    /// <remarks>applies constraints in aKeys.Constraints, if any</remarks>
    public bool AddKey(ISshKey aKey)
    {
      return AddKey(aKey, aKey.Constraints);
    }

    /// <summary>
    /// Adds key to SSH agent
    /// </summary>
    /// <param name="aKey">the key to add</param>
    /// <param name="aConstraints">constraints to apply</param>
    /// <returns>true if operation was successful</returns>
    /// <remarks>ignores constraints in aKey.Constraints</remarks>
    public bool AddKey(ISshKey aKey, ICollection<Agent.KeyConstraint> aConstraints)
    {
      var builder = CreatePrivateKeyBlob(aKey);
      if (aConstraints != null && aConstraints.Count > 0) {
        foreach (var constraint in aConstraints) {
          builder.AddByte((byte)constraint.Type);
          if (constraint.Type.GetDataType() == typeof(uint)) {
            builder.AddInt((uint)constraint.Data);
          }
        }
        switch (aKey.Version) {
          case SshVersion.SSH1:
            builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED);
            break;
          case SshVersion.SSH2:
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);
            break;
          default:
            throw new Exception(cUnsupportedSshVersion);
        }
      } else {
        switch (aKey.Version) {
          case SshVersion.SSH1:
            builder.InsertHeader(Agent.Message.SSH1_AGENTC_ADD_RSA_IDENTITY);
            break;
          case SshVersion.SSH2:
            builder.InsertHeader(Agent.Message.SSH2_AGENTC_ADD_IDENTITY);
            break;
          default:
            throw new Exception(cUnsupportedSshVersion);
        }
      }
      return SendMessage(builder);
    }

    /// <summary>
    /// Remove key from SSH agent
    /// </summary>
    /// <param name="aKey">The key to remove</param>
    /// <returns>true if removal succeeded</returns>
    public bool RemoveKey(ISshKey aKey)
    {
      var builder = CreatePublicKeyBlob(aKey);
      switch (aKey.Version) {
        case SshVersion.SSH1:
          builder.InsertHeader(Agent.Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY);
          break;
        case SshVersion.SSH2:
          builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_IDENTITY);
          break;
        default:
          throw new Exception(cUnsupportedSshVersion);
      }
      return SendMessage(builder);
    }

    public bool RemoveAllKeys(SshVersion aVersion)
    {
      BlobBuilder builder = new BlobBuilder();
      switch (aVersion) {
        case SshVersion.SSH1:
          builder.InsertHeader(Agent.Message.SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES);
          break;
        case SshVersion.SSH2:
          builder.InsertHeader(Agent.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
          break;
        default:
          throw new Exception(cUnsupportedSshVersion);
      }
      return SendMessage(builder);
    }

    public bool ListKeys(SshVersion aVersion,
      out ICollection<ISshKey> aKeyCollection)
    {
      BlobBuilder builder = new BlobBuilder();
      switch (aVersion) {
        case SshVersion.SSH1:
          builder.InsertHeader(Agent.Message.SSH1_AGENTC_REQUEST_RSA_IDENTITIES);
          break;
        case SshVersion.SSH2:
          builder.InsertHeader(Agent.Message.SSH2_AGENTC_REQUEST_IDENTITIES);
          break;
        default:
          throw new Exception(cUnsupportedSshVersion);
      }
      BlobParser replyParser;
      SendMessage(builder, out replyParser);
      aKeyCollection = new List<ISshKey>();
      try {
        var header = replyParser.ReadHeader();
        switch (aVersion) {
          case SshVersion.SSH1:
            if (header.Message != Agent.Message.SSH1_AGENT_RSA_IDENTITIES_ANSWER) {
              return false;
            }
            var ssh1KeyCount = replyParser.ReadInt();
            for (var i = 0; i < ssh1KeyCount; i++) {
              // TODO implement SSH1
            }
            break;
          case SshVersion.SSH2:
            if (header.Message != Agent.Message.SSH2_AGENT_IDENTITIES_ANSWER) {
              return false;
            }
            var ssh2KeyCount = replyParser.ReadInt();
            for (var i = 0; i < ssh2KeyCount; i++) {
              var publicKeyBlob = replyParser.ReadBlob();
              var publicKeyParams = Agent.ParseSsh2PublicKeyData(
                new MemoryStream(publicKeyBlob.Data));
              var comment = replyParser.ReadString();
              aKeyCollection.Add(
                new SshKey(SshVersion.SSH2, publicKeyParams, null, comment));
            }
            break;
          default:
            throw new Exception(cUnsupportedSshVersion);
        }
      } catch (Exception) {
        return false;
      }
      return true;
    }

    public bool SignRequest(ISshKey aKey, byte[] aSignData, out byte[] aSignature)
    {
      BlobBuilder builder = new BlobBuilder();
      switch (aKey.Version) {
        case SshVersion.SSH1:
          // TODO implement SSH1
          throw new NotImplementedException();
          builder.InsertHeader(Agent.Message.SSH1_AGENTC_RSA_CHALLENGE);
          break;
        case SshVersion.SSH2:
          builder.AddBlob(aKey.GetPublicKeyBlob());
          builder.AddBlob(aSignData);
          builder.InsertHeader(Agent.Message.SSH2_AGENTC_SIGN_REQUEST);
          break;
        default:
          throw new Exception(cUnsupportedSshVersion);
      }
      BlobParser replyParser;
      SendMessage(builder, out replyParser);
      aSignature = null;
      try {
        var header = replyParser.ReadHeader();
        switch (aKey.Version) {
          case SshVersion.SSH1:
            if (header.Message != Agent.Message.SSH1_AGENT_RSA_RESPONSE) {
              return false;
            }
            byte[] response = new byte[16];
            for (int i = 0; i < 16; i++) {
              response[i] = replyParser.ReadByte();
            }
            aSignature = response;
            break;
          case SshVersion.SSH2:
            if (header.Message != Agent.Message.SSH2_AGENT_SIGN_RESPONSE) {
              return false;
            }
            aSignature = replyParser.ReadBlob().Data;
            break;
          default:
            throw new Exception(cUnsupportedSshVersion);
        }
      } catch (Exception) {
        return false;
      }
      return true;
    }

    public bool Lock(byte[] aPassphrase)
    {
      BlobBuilder builder = new BlobBuilder();
      if (aPassphrase != null) {
        builder.AddBlob(aPassphrase);
      }
      builder.InsertHeader(Agent.Message.SSH_AGENTC_LOCK);
      return SendMessage(builder);
    }

    public bool Unlock(byte[] aPassphrase)
    {
      BlobBuilder builder = new BlobBuilder();
      if (aPassphrase != null) {
        builder.AddBlob(aPassphrase);
      }
      builder.InsertHeader(Agent.Message.SSH_AGENTC_UNLOCK);
      return SendMessage(builder);
    }

    private BlobBuilder CreatePublicKeyBlob(ISshKey aKey)
    {
      var builder = new BlobBuilder();
      builder.AddBlob(aKey.GetPublicKeyBlob());
      return builder;
    }

    private void SendMessage(BlobBuilder aBuilder, out BlobParser aReplyParser)
    {
      byte[] reply;
      using (var message = aBuilder.GetBlobAsPinnedByteArray()) {
        SendMessage(message.Data, out reply);
      }
      try {
        aReplyParser = new BlobParser(reply);
      } catch (Exception) {
        aReplyParser = null;
      }
    }

    private bool SendMessage(BlobBuilder aBuilder)
    {
      BlobParser replyParser;
      SendMessage(aBuilder, out replyParser);
      try {
        var header = replyParser.ReadHeader();
        if (header.Message != Agent.Message.SSH_AGENT_SUCCESS) {
          return false;
        }
      } catch (Exception) {
        return false;
      }
      return true;
    }

    private BlobBuilder CreatePrivateKeyBlob(ISshKey aKey)
    {
      var builder = new BlobBuilder();
      switch (aKey.Version) {
        case SshVersion.SSH2:
          builder.AddStringBlob(aKey.Algorithm.GetIdentifierString());
          switch (aKey.Algorithm) {
            case PublicKeyAlgorithm.SSH_DSS:
              var dsaPublicKeyParameters = aKey.GetPublicKeyParameters() as
                DsaPublicKeyParameters;
              var dsaPrivateKeyParamters = aKey.GetPrivateKeyParameters() as
                DsaPrivateKeyParameters;
              builder.AddBigIntBlob(dsaPublicKeyParameters.Parameters.P);
              builder.AddBigIntBlob(dsaPublicKeyParameters.Parameters.Q);
              builder.AddBigIntBlob(dsaPublicKeyParameters.Parameters.G);
              builder.AddBigIntBlob(dsaPublicKeyParameters.Y);
              builder.AddBigIntBlob(dsaPrivateKeyParamters.X);
              break;
            case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
            case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
            case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
              var ecdsaPublicKeyParameters = aKey.GetPublicKeyParameters() as
                ECPublicKeyParameters;
              var ecdsaPrivateKeyParameters = aKey.GetPrivateKeyParameters() as
                ECPrivateKeyParameters;
              builder.AddStringBlob(aKey.Algorithm.GetIdentifierString()
                .Replace(PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_PREFIX,
                         string.Empty));
              builder.AddBlob(ecdsaPublicKeyParameters.Q.GetEncoded());
              builder.AddBigIntBlob(ecdsaPrivateKeyParameters.D);
              break;
            case PublicKeyAlgorithm.SSH_RSA:
              var rsaPrivateKeyParameters = aKey.GetPrivateKeyParameters() as
                RsaPrivateCrtKeyParameters;
              builder.AddBigIntBlob(rsaPrivateKeyParameters.Modulus);
              builder.AddBigIntBlob(rsaPrivateKeyParameters.PublicExponent);
              builder.AddBigIntBlob(rsaPrivateKeyParameters.Exponent);
              builder.AddBigIntBlob(rsaPrivateKeyParameters.QInv);
              builder.AddBigIntBlob(rsaPrivateKeyParameters.P);
              builder.AddBigIntBlob(rsaPrivateKeyParameters.Q);
              break;
            default:
              throw new Exception("Unsupported algorithm");
          }
          break;
        default:
          throw new Exception(cUnsupportedSshVersion);
      }
      builder.AddStringBlob(aKey.Comment);
      return builder;
    }

  }
}
