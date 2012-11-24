using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Text;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Class for encapsulating information on encryption keys so that it can be
  /// used in PuTTY related programs
  /// </summary>
  public class SshKey : ISshKey
  {
    private List<Agent.KeyConstraint> mKeyConstraints;
    private AsymmetricCipherKeyPair mCipherKeyPair;

    public SshKey(SshVersion aVersion, AsymmetricCipherKeyPair aCipherKeyPair,
      string aComment = "")
    {
      Version = aVersion;
      mCipherKeyPair = aCipherKeyPair;
      Comment = aComment;
      mKeyConstraints = new List<Agent.KeyConstraint>();
    }

    public SshVersion Version { get; private set; }
    
    public PublicKeyAlgorithm Algorithm
    {
      get
      {
        if (mCipherKeyPair.Public is RsaKeyParameters) {
          return PublicKeyAlgorithm.SSH_RSA;
        } else if (mCipherKeyPair.Public is DsaPublicKeyParameters) {
          return PublicKeyAlgorithm.SSH_DSS;
        } else if (mCipherKeyPair.Public is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)mCipherKeyPair.Public;
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
        if (mCipherKeyPair.Public is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)mCipherKeyPair.Public;
          return rsaKeyParameters.Modulus.BitLength;
        } else if (mCipherKeyPair.Public is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)mCipherKeyPair.Public;
          return dsaKeyParameters.Parameters.P.BitLength;
        } else if (mCipherKeyPair.Public is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)mCipherKeyPair.Public;
          return ecdsaParameters.Q.Curve.FieldSize;
        }
        // TODO need a better exception here
        throw new Exception("Not Defined");
      }
    }

    public byte[] MD5Fingerprint
    {
      get
      {
        try {
          using (MD5 md5 = MD5.Create()) {
            return md5.ComputeHash(this.GetPublicKeyBlob());
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

    public ReadOnlyCollection<Agent.KeyConstraint> Constraints
    {
      get
      {
        return mKeyConstraints.AsReadOnly();
      }
    }

    public AsymmetricKeyParameter GetPublicKeyParameters()
    {
      return mCipherKeyPair.Public;
    }

    public AsymmetricKeyParameter GetPrivateKeyParameters()
    {
      return mCipherKeyPair.Private;
    }

    public void AddConstraint(Agent.KeyConstraint aConstraint)
    {
      mKeyConstraints.Add(aConstraint);
    }
    
    ~SshKey()
    {
      this.Dispose();
    }

    public void Dispose()
    {
      if (this.mCipherKeyPair != null) {
        // TODO is there a way to clear parameters from memory?
      }
    }


    public SshKey Clone()
    {
      AsymmetricCipherKeyPair keyPair = new AsymmetricCipherKeyPair(
        GetPublicKeyParameters(), GetPrivateKeyParameters());
      SshKey newKey = new SshKey(Version, keyPair, Comment);
      foreach (Agent.KeyConstraint constraint in mKeyConstraints) {
        newKey.AddConstraint(constraint);
      }
      return newKey;
    }
  }
}
