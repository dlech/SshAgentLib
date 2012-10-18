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

    /// <summary>
    /// Contains fields with valid public key encryption algorithms
    /// </summary>
    public static class PublicKeyAlgorithms
    {
      public const string ssh_rsa = "ssh-rsa";
      public const string ssh_dss = "ssh-dss";
    }

    public AsymmetricCipherKeyPair KeyParameters {
      get;
      set;
    }

    public int Size {
      get {
        if (KeyParameters.Public is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)KeyParameters.Public;
          return rsaKeyParameters.Modulus.BitLength;
        }
        if (KeyParameters.Public is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)KeyParameters.Public;
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
      if (this.KeyParameters != null) {
        // TODO is there a way to clear parameters from memory?
      }
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
    public byte[] GetSSH2PublicKeyBlob()
    {

      if (KeyParameters.Public is RsaKeyParameters) {
                                
        RsaKeyParameters rsaKeyParameters =
          (RsaKeyParameters)KeyParameters.Public;
        PpkKeyBlobBuilder builder = new PpkKeyBlobBuilder();

        builder.AddString(PpkKey.PublicKeyAlgorithms.ssh_rsa);
        builder.AddBigInt(rsaKeyParameters.Exponent);
        builder.AddBigInt(rsaKeyParameters.Modulus);

        byte[] result = builder.getBlob();
        builder.Clear();
        return result;
      }

      if (KeyParameters.Public is DsaPublicKeyParameters) {

        DsaPublicKeyParameters dsaParameters =
          (DsaPublicKeyParameters)KeyParameters.Public;
        PpkKeyBlobBuilder builder = new PpkKeyBlobBuilder();

        builder.AddString(PpkKey.PublicKeyAlgorithms.ssh_dss);
        builder.AddBigInt(dsaParameters.Parameters.P);
        builder.AddBigInt(dsaParameters.Parameters.Q);
        builder.AddBigInt(dsaParameters.Parameters.G);
        builder.AddBigInt(dsaParameters.Y);

        byte[] result = builder.getBlob();
        builder.Clear();
        return result;
      }

      throw new ArgumentException(KeyParameters.GetType() +
                                  " is not supported", "alg");
    }


    /// <summary>
    /// Gets openssh style fingerprint for key.
    /// </summary>
    /// <returns>byte array containing fingerprint data</returns>
    /// <exception cref="System.ArgumentException">
    /// If Algorithm is not supported
    /// </exception>
    public byte[] GetFingerprint()
    {
      if (KeyParameters.Public is RsaKeyParameters ||
          KeyParameters.Public is DsaPublicKeyParameters) {
        using (MD5 md5 = MD5.Create()) {
          return md5.ComputeHash(GetSSH2PublicKeyBlob());
        }
      }      
      throw new ArgumentException(KeyParameters.GetType() +
                                  " is not supported", "alg");
    }
  }
}
