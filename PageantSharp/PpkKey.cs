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
  public class PpkKey : IDisposable
  {       

    public AsymmetricCipherKeyPair CipherKeyPair {
      get;
      set;
    }

    public int Size {
      get {
        if (CipherKeyPair.Public is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)CipherKeyPair.Public;
          return rsaKeyParameters.Modulus.BitLength;
        }
        if (CipherKeyPair.Public is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)CipherKeyPair.Public;
          return dsaKeyParameters.Parameters.P.BitLength;
        }
        // TODO need a better exception here
        throw new Exception("Not Defined");
      }
    }

    /// <summary>
    /// User comment
    /// </summary>
    public string Comment {
      get;
      set;
    }

    ~PpkKey()
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
