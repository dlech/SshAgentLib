using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Pkcs;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Public Key Algorithms supports by SSH
  /// </summary>
  public enum PublicKeyAlgorithm
  {
    SSH_RSA,
    SSH_DSS,
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521
  }

  public static class PublicKeyAlgorithmExt
  {
    /* defined by RFC 4253 - http://www.ietf.org/rfc/rfc4253.txt */
    public const string ALGORITHM_DSA_KEY = "ssh-dss";
    public const string ALGORITHM_RSA_KEY = "ssh-rsa";
    public const string ALGORITHM_PGP_RSA_SIGN_CERT = "pgp-sign-rsa";
    public const string ALGORITHM_PGP_DSA_SIGN_CERT = "pgp-sign-dss";

    /* defined by OpenSSH PROTOCOL.agent - http://api.libssh.org/rfc/PROTOCOL.agent */
    public const string OPENSSH_CERT_V00_SUFFIX = "-cert-v00@openssh.com";
    public const string OPENSSH_CERT_V01_SUFFIX = "-cert-v01@openssh.com";
    //public const string ALGORITHM_DSA_KEY = "ssh-dss";
    public const string ALGORITHM_DSA_CERT = 
      ALGORITHM_DSA_KEY + OPENSSH_CERT_V00_SUFFIX;
    //public const string ALGORITHM_RSA_KEY = "ssh-rsa";
    public const string ALGORITHM_RSA_CERT = ALGORITHM_DSA_KEY + OPENSSH_CERT_V00_SUFFIX;
    public const string ALGORITHM_ECDSA_SHA2_PREFIX = "ecdsa-sha2-";
    public const string EC_ALGORITHM_NISTP256 = "nistp256";
    public const string EC_ALGORITHM_NISTP384 = "nistp384";
    public const string EC_ALGORITHM_NISTP521 = "nistp521";
    public const string ALGORITHM_ECDSA_SHA2_NISTP256_KEY =
      ALGORITHM_ECDSA_SHA2_PREFIX + EC_ALGORITHM_NISTP256;
    public const string ALGORITHM_ECDSA_SHA2_NISTP384_KEY =
      ALGORITHM_ECDSA_SHA2_PREFIX + EC_ALGORITHM_NISTP384;
    public const string ALGORITHM_ECDSA_SHA2_NISTP521_KEY =
      ALGORITHM_ECDSA_SHA2_PREFIX + EC_ALGORITHM_NISTP521;
    public const string ALGORITHM_ECDSA_SHA2_NISTP256_CERT =
      ALGORITHM_ECDSA_SHA2_PREFIX + EC_ALGORITHM_NISTP256 + OPENSSH_CERT_V01_SUFFIX;
    public const string ALGORITHM_ECDSA_SHA2_NISTP384_CERT =
      ALGORITHM_ECDSA_SHA2_PREFIX + EC_ALGORITHM_NISTP384 + OPENSSH_CERT_V01_SUFFIX;
    public const string ALGORITHM_ECDSA_SHA2_NISTP521_CERT =
      ALGORITHM_ECDSA_SHA2_PREFIX + EC_ALGORITHM_NISTP521 + OPENSSH_CERT_V01_SUFFIX;
    

    public static string GetIdentifierString(this PublicKeyAlgorithm aPublicKeyAlgorithm)
    {
      switch (aPublicKeyAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          return ALGORITHM_RSA_KEY;
        case PublicKeyAlgorithm.SSH_DSS:
          return ALGORITHM_DSA_KEY;
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
          return ALGORITHM_ECDSA_SHA2_NISTP256_KEY;
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
          return ALGORITHM_ECDSA_SHA2_NISTP384_KEY;
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
          return ALGORITHM_ECDSA_SHA2_NISTP521_KEY;
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }

    public static ISigner GetSigner(this PublicKeyAlgorithm aPublicKeyAlgorithm)
    {
      switch (aPublicKeyAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id);
        case PublicKeyAlgorithm.SSH_DSS:
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.IdDsaWithSha1.Id);
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha256.Id);
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha384.Id);
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha512.Id);
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }
  }
}
