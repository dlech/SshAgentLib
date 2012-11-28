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
    private AsymmetricKeyParameter mPublicKeyParameter;
    private AsymmetricKeyParameter mPrivateKeyParameter;

    public SshKey(SshVersion aVersion, AsymmetricKeyParameter aPublicKeyParameter,
      AsymmetricKeyParameter aPrivateKeyParameter = null, string aComment = "")
    {      
      if (aPublicKeyParameter == null) {
        throw new ArgumentNullException("aPublicKeyParameter");
      }
      IsPublicOnly = (aPrivateKeyParameter == null);
      Version = aVersion;
      mPublicKeyParameter = aPublicKeyParameter;
      mPrivateKeyParameter = aPrivateKeyParameter;
      Comment = aComment;
      mKeyConstraints = new List<Agent.KeyConstraint>();
    }

    public SshKey(SshVersion aVersion, AsymmetricCipherKeyPair aCipherKeyPair,
      string aComment = "")
      : this(aVersion, aCipherKeyPair.Public, aCipherKeyPair.Private, aComment) { }
    

    public SshVersion Version { get; private set; }

    public PublicKeyAlgorithm Algorithm
    {
      get
      {
        if (mPublicKeyParameter is RsaKeyParameters) {
          return PublicKeyAlgorithm.SSH_RSA;
        } else if (mPublicKeyParameter is DsaPublicKeyParameters) {
          return PublicKeyAlgorithm.SSH_DSS;
        } else if (mPublicKeyParameter is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)mPublicKeyParameter;
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

    public bool IsPublicOnly { get; private set; }

    public int Size
    {
      get
      {
        if (mPublicKeyParameter is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)mPublicKeyParameter;
          return rsaKeyParameters.Modulus.BitLength;
        } else if (mPublicKeyParameter is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)mPublicKeyParameter;
          return dsaKeyParameters.Parameters.P.BitLength;
        } else if (mPublicKeyParameter is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)mPublicKeyParameter;
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
      return mPublicKeyParameter;
    }

    public AsymmetricKeyParameter GetPrivateKeyParameters()
    {
      return mPrivateKeyParameter;
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
        // TODO is there a way to clear parameters from memory?
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
