using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.Math;

namespace dlech.PageantSharp
{
  public static class OpenSsh
  {

    /* Protocol message number - from PROTOCOL.agent in openssh source code */

    public enum Message : byte
    {
      /* Requests from client to agent for protocol 1 key operations */
      SSH1_AGENTC_REQUEST_RSA_IDENTITIES = 1,
      SSH1_AGENTC_RSA_CHALLENGE = 3,
      SSH1_AGENTC_ADD_RSA_IDENTITY = 7,
      SSH1_AGENTC_REMOVE_RSA_IDENTITY = 8,
      SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9,
      SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED = 24,

      /* Requests from client to agent for protocol 2 key operations */
      SSH2_AGENTC_REQUEST_IDENTITIES = 11,
      SSH2_AGENTC_SIGN_REQUEST = 13,
      SSH2_AGENTC_ADD_IDENTITY = 17,
      SSH2_AGENTC_REMOVE_IDENTITY = 18,
      SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19,
      SSH2_AGENTC_ADD_ID_CONSTRAINED = 25,

      /* Key-type independent requests from client to agent */
      SSH_AGENTC_ADD_SMARTCARD_KEY = 20,
      SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21,
      SSH_AGENTC_LOCK = 22,
      SSH_AGENTC_UNLOCK = 23,
      SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26,
    
      /* Generic replies from agent to client */
      SSH_AGENT_FAILURE = 5,
      SSH_AGENT_SUCCESS = 6,

      /* Replies from agent to client for protocol 1 key operations */
      SSH1_AGENT_RSA_IDENTITIES_ANSWER = 2,
      SSH1_AGENT_RSA_RESPONSE = 4,

      /* Replies from agent to client for protocol 2 key operations */
      SSH2_AGENT_IDENTITIES_ANSWER = 12,
      SSH2_AGENT_SIGN_RESPONSE = 14
    }

    public enum KeyConstraint : byte
    {
      /* Key constraint identifiers */
      SSH_AGENT_CONSTRAIN_LIFETIME = 1,
      SSH_AGENT_CONSTRAIN_CONFIRM = 2
    }

    public struct BlobHeader
    {
      public int BlobLength { get; set; }
      public Message Message { get; set; }
    }
      
    /// <summary>
    /// Contains fields with valid public key encryption algorithms
    /// </summary>
    public static class PublicKeyAlgorithms
    {
      public const string ssh_rsa = "ssh-rsa";
      public const string ssh_dss = "ssh-dss";
    }

    /// <summary>
    /// Gets PuTTY formatted bytes from public key
    /// </summary>
    /// <param name="Algorithm">AsymmetricAlgorithm to convert.
    /// (Currently only supports RSA)</param>
    /// <returns>byte array</returns>
    /// <exception cref="ArgumentException">
    /// AsymmetricAlgorithm is not supported
    /// </exception>
    public static byte[] GetSSH2PublicKeyBlob(AsymmetricCipherKeyPair aCipherKeyPair)
    {

      if (aCipherKeyPair.Public is RsaKeyParameters) {

        RsaKeyParameters rsaKeyParameters =
          (RsaKeyParameters)aCipherKeyPair.Public;
        BlobBuilder builder = new BlobBuilder();

        builder.AddString(OpenSsh.PublicKeyAlgorithms.ssh_rsa);
        builder.AddBigInt(rsaKeyParameters.Exponent);
        builder.AddBigInt(rsaKeyParameters.Modulus);

        byte[] result = builder.GetBlob();
        builder.Clear();
        return result;
      }

      if (aCipherKeyPair.Public is DsaPublicKeyParameters) {

        DsaPublicKeyParameters dsaParameters =
          (DsaPublicKeyParameters)aCipherKeyPair.Public;
        BlobBuilder builder = new BlobBuilder();

        builder.AddString(OpenSsh.PublicKeyAlgorithms.ssh_dss);
        builder.AddBigInt(dsaParameters.Parameters.P);
        builder.AddBigInt(dsaParameters.Parameters.Q);
        builder.AddBigInt(dsaParameters.Parameters.G);
        builder.AddBigInt(dsaParameters.Y);

        byte[] result = builder.GetBlob();
        builder.Clear();
        return result;
      }

      throw new ArgumentException(aCipherKeyPair.GetType() + " is not supported");
    }

    /// <summary>
    /// Gets openssh style fingerprint for key.
    /// </summary>
    /// <returns>byte array containing fingerprint data</returns>
    /// <exception cref="System.ArgumentException">
    /// If Algorithm is not supported
    /// </exception>
    public static byte[] GetFingerprint(AsymmetricCipherKeyPair aCipherKeyPair)
    {
      if (aCipherKeyPair.Public is RsaKeyParameters ||
          aCipherKeyPair.Public is DsaPublicKeyParameters) {
        using (MD5 md5 = MD5.Create()) {
          return md5.ComputeHash(GetSSH2PublicKeyBlob(aCipherKeyPair));
        }
      }
      throw new ArgumentException(aCipherKeyPair.GetType() + " is not supported");
    }

    public static AsymmetricCipherKeyPair CreateCipherKeyPair(Stream aSteam)
    {
      BlobParser parser = new BlobParser(aSteam);

      string algorithm = Encoding.UTF8.GetString(parser.Read());

      switch (algorithm) {
        case OpenSsh.PublicKeyAlgorithms.ssh_rsa:
          BigInteger n = new BigInteger(1, parser.Read()); // modulus
          BigInteger e = new BigInteger(1, parser.Read()); // exponent
          BigInteger d = new BigInteger(1, parser.Read());
          BigInteger iqmp = new BigInteger(1, parser.Read());
          BigInteger p = new BigInteger(1, parser.Read());
          BigInteger q = new BigInteger(1, parser.Read());

          /* compute missing parameters */
          BigInteger dp = d.Remainder(p.Subtract(BigInteger.One));
          BigInteger dq = d.Remainder(q.Subtract(BigInteger.One));

          RsaKeyParameters rsaPublicKeyParams = new RsaKeyParameters(false, n, e);
          RsaPrivateCrtKeyParameters rsaPrivateKeyParams =
            new RsaPrivateCrtKeyParameters(n, e, d, p, q, dp, dq, iqmp);

          return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);

        case OpenSsh.PublicKeyAlgorithms.ssh_dss:
          /*BigInteger*/
          p = new BigInteger(1, parser.Read());
          /*BigInteger*/
          q = new BigInteger(1, parser.Read());
          BigInteger g = new BigInteger(1, parser.Read());
          BigInteger y = new BigInteger(1, parser.Read()); // public key
          //PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
          BigInteger x = new BigInteger(1, parser.Read()); // private key
          //parser.MoveNext();

          DsaParameters commonParams = new DsaParameters(p, q, g);
          DsaPublicKeyParameters dsaPublicKeyParams =
            new DsaPublicKeyParameters(y, commonParams);
          DsaPrivateKeyParameters dsaPrivateKeyParams =
            new DsaPrivateKeyParameters(x, commonParams);

          return new AsymmetricCipherKeyPair(dsaPublicKeyParams, dsaPrivateKeyParams);

        default:
          // unsupported encryption algorithm
          throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
      }
    }

  }
}
