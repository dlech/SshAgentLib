using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.Math;
using System.Diagnostics;

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

    public enum KeyConstraintType : byte
    {
      /* Key constraint identifiers */
      SSH_AGENT_CONSTRAIN_LIFETIME = 1,
      SSH_AGENT_CONSTRAIN_CONFIRM = 2
    }

    public static Type GetDataType(this KeyConstraintType aConstraint)
    {
      switch (aConstraint) {
        case KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM :
          return null;
        case KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME:
          return typeof(UInt32);
        default:
          Debug.Fail("Unknown KeyConstraintType");
          throw new ArgumentException("Unknown KeyConstraintType");
      }
    }

    public struct KeyConstraint
    {
      public KeyConstraintType Type { get; set; }
      public Object Data { get; set; }
    }    

    public const string ALGORITHM_DSA_KEY = "ssh-dss";
    public const string ALGORITHM_DSA_CERT = "ssh-dss-cert-v00@openssh.com";
    public const string ALGORITHM_ECDSA_SHA2_NISTP256_KEY = "ecdsa-sha2-nistp256";
    public const string ALGORITHM_ECDSA_SHA2_NISTP384_KEY = "ecdsa-sha2-nistp384";
    public const string ALGORITHM_ECDSA_SHA2_NISTP521_KEY = "ecdsa-sha2-nistp521";
    public const string ALGORITHM_ECDSA_SHA2_NISTP256_CERT = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
    public const string ALGORITHM_ECDSA_SHA2_NISTP384_CERT = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
    public const string ALGORITHM_ECDSA_SHA2_NISTP521_CERT = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
    public const string ALGORITHM_RSA_KEY = "ssh-rsa";
    public const string ALGORITHM_RSA_CERT = "ssh-rsa-cert-v00@openssh.com";

    /// <summary>
    /// Valid public key encryption algorithms
    /// </summary>
    public enum PublicKeyAlgorithm
    {
      SSH_RSA,  
      SSH_DSS 
    }

    public static string GetName(this PublicKeyAlgorithm aPublicKeyAlgorithm) {
      switch (aPublicKeyAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          return ALGORITHM_RSA_KEY;
        case PublicKeyAlgorithm.SSH_DSS:
          return ALGORITHM_DSA_KEY;
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }

    public struct BlobHeader
    {
      public UInt32 BlobLength { get; set; }
      public Message Message { get; set; }
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

        builder.AddString(OpenSsh.PublicKeyAlgorithm.SSH_RSA.GetName());
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

        builder.AddString(OpenSsh.PublicKeyAlgorithm.SSH_DSS.GetName());
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
    /// Gets OpenSSH style fingerprint for key.
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

      string algorithm = Encoding.UTF8.GetString(parser.ReadBlob().Data);

      switch (algorithm) {
        case ALGORITHM_RSA_KEY:
          BigInteger n = new BigInteger(1, parser.ReadBlob().Data); // modulus
          BigInteger e = new BigInteger(1, parser.ReadBlob().Data); // exponent
          BigInteger d = new BigInteger(1, parser.ReadBlob().Data);
          BigInteger iqmp = new BigInteger(1, parser.ReadBlob().Data);
          BigInteger p = new BigInteger(1, parser.ReadBlob().Data);
          BigInteger q = new BigInteger(1, parser.ReadBlob().Data);

          /* compute missing parameters */
          BigInteger dp = d.Remainder(p.Subtract(BigInteger.One));
          BigInteger dq = d.Remainder(q.Subtract(BigInteger.One));

          RsaKeyParameters rsaPublicKeyParams = new RsaKeyParameters(false, n, e);
          RsaPrivateCrtKeyParameters rsaPrivateKeyParams =
            new RsaPrivateCrtKeyParameters(n, e, d, p, q, dp, dq, iqmp);

          return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);

        case ALGORITHM_DSA_KEY:
          /*BigInteger*/
          p = new BigInteger(1, parser.ReadBlob().Data);
          /*BigInteger*/
          q = new BigInteger(1, parser.ReadBlob().Data);
          BigInteger g = new BigInteger(1, parser.ReadBlob().Data);
          BigInteger y = new BigInteger(1, parser.ReadBlob().Data); // public key
          BigInteger x = new BigInteger(1, parser.ReadBlob().Data); // private key

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
