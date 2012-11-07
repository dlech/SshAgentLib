using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Text;

namespace dlech.PageantSharp
{
  /// <summary>
  /// Class for encapsulating information on encryption keys so that it can be
  /// used in PuTTY related programs
  /// </summary>
  public class SshKey : ISshKey
  {

    public SshVersion Version { get; set; }

    public AsymmetricCipherKeyPair CipherKeyPair {
      get;
      set;
    }

    public PublicKeyAlgorithm Algorithm
    {
      get
      {
        if (CipherKeyPair.Public is RsaKeyParameters) {
          return PublicKeyAlgorithm.SSH_RSA;
        } else if (CipherKeyPair.Public is DsaPublicKeyParameters) {
          return PublicKeyAlgorithm.SSH_DSS;
        }
        throw new Exception("Unknown algorithm");
      }
    }

    public int Size {
      get {
        if (CipherKeyPair.Public is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)CipherKeyPair.Public;
          return rsaKeyParameters.Modulus.BitLength;
        } else if (CipherKeyPair.Public is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)CipherKeyPair.Public;
          return dsaKeyParameters.Parameters.P.BitLength;
        }
        // TODO need a better exception here
        throw new Exception("Not Defined");
      }
    }

    public byte[] Fingerprint
    {
      get
      {
        try {
          return OpenSsh.GetFingerprint(CipherKeyPair);
        } catch (Exception) {
          return null;
        }
      }
    }

    /// <summary>
    /// User comment
    /// </summary>
    public string Comment {
      get;
      set;
    }

    ~SshKey()
    {
      this.Dispose();
    }

    public void Dispose()
    {
      if (this.CipherKeyPair != null) {
        // TODO is there a way to clear parameters from memory?
      }
    }

  }
}
