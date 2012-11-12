using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Text;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace dlech.PageantSharp
{
  /// <summary>
  /// Class for encapsulating information on encryption keys so that it can be
  /// used in PuTTY related programs
  /// </summary>
  public class SshKey : ISshKey
  {
    private ObservableCollection<Agent.KeyConstraint> mKeyConstraints =
      new ObservableCollection<Agent.KeyConstraint>();

    public SshVersion Version { get; set; }

    public AsymmetricCipherKeyPair CipherKeyPair
    {
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
        } else if (CipherKeyPair.Public is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)CipherKeyPair.Public;
          switch (ecdsaParameters.Q.Curve.FieldSize) {
            case 256:
              return PublicKeyAlgorithm.ECDSA_SHA2_NISTP256;
            case 384:
              return PublicKeyAlgorithm.ECDSA_SHA2_NISTP384;
            case 521:
              return PublicKeyAlgorithm.ECDSA_SHA2_NISTP521;
          }
        }
        throw new Exception("Unknown algorithm");
      }
    }

    public int Size
    {
      get
      {
        if (CipherKeyPair.Public is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)CipherKeyPair.Public;
          return rsaKeyParameters.Modulus.BitLength;
        } else if (CipherKeyPair.Public is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)CipherKeyPair.Public;
          return dsaKeyParameters.Parameters.P.BitLength;
        } else if (CipherKeyPair.Public is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)CipherKeyPair.Public;
          return ecdsaParameters.Q.Curve.FieldSize;
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
          using (MD5 md5 = MD5.Create()) {
            return md5.ComputeHash(CipherKeyPair.Public.ToBlob());
          }
        } catch (Exception) {
          return null;
        }
      }
    }

    /// <summary>
    /// User comment
    /// </summary>
    public string Comment
    {
      get;
      set;
    }

    public ObservableCollection<Agent.KeyConstraint> Constraints
    {
      get
      {
        return mKeyConstraints;
      }
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
