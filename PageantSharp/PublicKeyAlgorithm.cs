using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace dlech.PageantSharp
{
  /// <summary>
  /// Public Key Algorithms supports by SSH
  /// </summary>
  public enum PublicKeyAlgorithm
  {
    SSH_RSA,
    SSH_DSS
    // TODO implement other algorithms
  }

  public static class PublicKeyAlgorithmExt
  {
    /* defined by RFC 4253 - http://www.ietf.org/rfc/rfc4253.txt */
    public const string ALGORITHM_DSA_KEY = "ssh-dss";
    public const string ALGORITHM_RSA_KEY = "ssh-rsa";
    public const string ALGORITHM_PGP_RSA_SIGN_CERT = "pgp-sign-rsa";
    public const string ALGORITHM_PGP_DSA_SIGN_CERT = "pgp-sign-dss";

    /* defined by OpenSSH PROTOCOL.agent - http://api.libssh.org/rfc/PROTOCOL.agent */
    //public const string ALGORITHM_DSA_KEY = "ssh-dss";
    //public const string ALGORITHM_RSA_KEY = "ssh-rsa";
    public const string ALGORITHM_DSA_CERT = "ssh-dss-cert-v00@openssh.com";
    public const string ALGORITHM_ECDSA_SHA2_NISTP256_KEY = "ecdsa-sha2-nistp256";
    public const string ALGORITHM_ECDSA_SHA2_NISTP384_KEY = "ecdsa-sha2-nistp384";
    public const string ALGORITHM_ECDSA_SHA2_NISTP521_KEY = "ecdsa-sha2-nistp521";
    public const string ALGORITHM_ECDSA_SHA2_NISTP256_CERT = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
    public const string ALGORITHM_ECDSA_SHA2_NISTP384_CERT = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
    public const string ALGORITHM_ECDSA_SHA2_NISTP521_CERT = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
    public const string ALGORITHM_RSA_CERT = "ssh-rsa-cert-v00@openssh.com";

    public static string GetIdentifierString(this PublicKeyAlgorithm aPublicKeyAlgorithm)
    {
      switch (aPublicKeyAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          return ALGORITHM_RSA_KEY;
        case PublicKeyAlgorithm.SSH_DSS:
          return ALGORITHM_DSA_KEY;
        // TODO implement other algorithms
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }

    public static ISigner GetSigner(this PublicKeyAlgorithm aPublicKeyAlgorithm)
    {
      switch (aPublicKeyAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          return SignerUtilities.GetSigner("SHA-1withRSA");
        case PublicKeyAlgorithm.SSH_DSS:
          return SignerUtilities.GetSigner("SHA-1withDSA");
        // TODO implement other algorithms
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }
  }
}
