using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Runtime.InteropServices;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Sec;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// used to parse open-ssh blobs
  /// </summary>
  public class BlobParser
  {
    public Stream Stream { get; private set; }

    public BlobParser(byte[] aBlob) : this(new MemoryStream(aBlob)) { }

    public BlobParser(Stream aStream)
    {
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }
      Stream = aStream;
    }

    public byte ReadByte()
    {
      if (Stream.Length - Stream.Position < 1) {
        throw new Exception("Not enough data");
      }
      return (byte)Stream.ReadByte();
    }

    public UInt32 ReadInt()
    {
      byte[] dataLegthBytes = new byte[4];
      if (Stream.Length - Stream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      return dataLegthBytes.ToInt();
    }

    public UInt16 ReadShort()
    {
        byte[] dataLegthBytes = new byte[2];
        if (Stream.Length - Stream.Position < dataLegthBytes.Length)
        {
            throw new Exception("Not enough data");
        }
        Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
        return (ushort)((dataLegthBytes[0] << 8) + dataLegthBytes[1]);
    }

    public Agent.BlobHeader ReadHeader()
    {
      Agent.BlobHeader header = new Agent.BlobHeader();

      header.BlobLength = ReadInt();
      if (Stream.Length - Stream.Position < header.BlobLength) {
        throw new Exception("Not enough data");
      }
      header.Message = (Agent.Message)ReadByte();
      return header;
    }

    public string ReadString()
    {
      return Encoding.UTF8.GetString(ReadBlob().Data);
    }

    public PinnedByteArray ReadBlob()
    {
        return ReadBytes(ReadInt());
    }

    public PinnedByteArray ReadSsh1BigIntBlob()
    {
      var bitCount = ReadShort();
      return ReadBits(bitCount);
    }

    public PinnedByteArray ReadBits(UInt32 aBitCount)
    {
      return ReadBytes((aBitCount + (uint)7) / 8);
    }

    public PinnedByteArray ReadBytes(UInt32 blobLength)
    {
        if (Stream.Length - Stream.Position < blobLength)
        {
            throw new Exception("Not enough data");
        }
        PinnedByteArray blob = new PinnedByteArray((int)blobLength);
        Stream.Read(blob.Data, 0, blob.Data.Length);
        return blob;
    }


    /// <summary>
    /// reads OpenSSH formatted public key blob and creates
    /// an AsymmetricKeyParameter object
    /// </summary>
    /// <param name="aReverseRsaParameters">
    /// Set to true to read RSA modulus first. Normally exponent is read first.
    /// Has no effect on other algorithms
    /// </param>
    /// <returns>AsymmetricKeyParameter containing the public key</returns>
    public AsymmetricKeyParameter ReadSsh2PublicKeyData(
      bool aReverseRsaParameters = false)
    {
      var algorithm = Encoding.UTF8.GetString(ReadBlob().Data);

      switch (algorithm) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY:
          var rsaE = new BigInteger(1, ReadBlob().Data); // exponent
          var rsaN = new BigInteger(1, ReadBlob().Data); // modulus
          if (aReverseRsaParameters) {
            return new RsaKeyParameters(false, rsaE, rsaN);
          }
          return new RsaKeyParameters(false, rsaN, rsaE);

        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY:
          var dsaP = new BigInteger(1, ReadBlob().Data);
          var dsaQ = new BigInteger(1, ReadBlob().Data);
          var dsaG = new BigInteger(1, ReadBlob().Data);
          var dsaY = new BigInteger(1, ReadBlob().Data); // public key

          var dsaParams = new DsaParameters(dsaP, dsaQ, dsaG);
          return new DsaPublicKeyParameters(dsaY, dsaParams);

        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_KEY:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_KEY:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_KEY:

          var ecdsaCurveName = ReadString();
          var ecdsaPublicKey = ReadBlob().Data;

          switch (ecdsaCurveName) {
            case PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP256:
              ecdsaCurveName = "secp256r1";
              break;
            case PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP384:
              ecdsaCurveName = "secp384r1";
              break;
            case PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP521:
              ecdsaCurveName = "secp521r1";
              break;
            default:
              throw new Exception("Unsupported EC algorithm: " + ecdsaCurveName);
          }
          var ecdsaX9Params = SecNamedCurves.GetByName(ecdsaCurveName);
          var ecdsaDomainParams = new ECDomainParameters(ecdsaX9Params.Curve,
            ecdsaX9Params.G, ecdsaX9Params.N, ecdsaX9Params.H);
          var ecdsaPoint = ecdsaX9Params.Curve.DecodePoint(ecdsaPublicKey);
          return new ECPublicKeyParameters(ecdsaPoint, ecdsaDomainParams);

        default:
          // unsupported encryption algorithm
          throw new Exception("Unsupported algorithm");
      }
    }

    /// <summary>
    /// reads private key portion of OpenSSH formatted key blob from stream and
    /// creates a key pair
    /// </summary>
    /// <returns>key pair</returns>
    /// <remarks>
    /// intended to be called immediately after ParseSsh2PublicKeyData
    /// </remarks>
    public AsymmetricCipherKeyPair ReadSsh2KeyData(
      AsymmetricKeyParameter aPublicKeyParameter)
    {
      if (aPublicKeyParameter is RsaKeyParameters) {
        var rsaD = new BigInteger(1, ReadBlob().Data);
        var rsaIQMP = new BigInteger(1, ReadBlob().Data);
        var rsaP = new BigInteger(1, ReadBlob().Data);
        var rsaQ = new BigInteger(1, ReadBlob().Data);

        /* compute missing parameters */
        var rsaDP = rsaD.Remainder(rsaP.Subtract(BigInteger.One));
        var rsaDQ = rsaD.Remainder(rsaQ.Subtract(BigInteger.One));

        var rsaPublicKeyParams = aPublicKeyParameter as RsaKeyParameters;
        var rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
          rsaPublicKeyParams.Modulus, rsaPublicKeyParams.Exponent,
          rsaD, rsaP, rsaQ, rsaDP, rsaDQ, rsaIQMP);

        return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);
      } else if (aPublicKeyParameter is DsaPublicKeyParameters) {
        var dsaX = new BigInteger(1, ReadBlob().Data); // private key

        var dsaPublicKeyParams = aPublicKeyParameter as DsaPublicKeyParameters;
        DsaPrivateKeyParameters dsaPrivateKeyParams =
          new DsaPrivateKeyParameters(dsaX, dsaPublicKeyParams.Parameters);

        return new AsymmetricCipherKeyPair(dsaPublicKeyParams, dsaPrivateKeyParams);
      } else if (aPublicKeyParameter is ECPublicKeyParameters) {
        var ecdsaPrivate = new BigInteger(1, ReadBlob().Data);

        var ecPublicKeyParams = aPublicKeyParameter as ECPublicKeyParameters;
        ECPrivateKeyParameters ecPrivateKeyParams =
          new ECPrivateKeyParameters(ecdsaPrivate, ecPublicKeyParams.Parameters);

        return new AsymmetricCipherKeyPair(ecPublicKeyParams, ecPrivateKeyParams);
      } else {
        // unsupported encryption algorithm
        throw new Exception("Unsupported algorithm");
      }
    }

    /// <summary>
    /// reads ssh1 OpenSSH formatted public key blob from stream and creates 
    /// an AsymmetricKeyParameter object
    /// </summary>
    /// <param name="Stream">stream to parse</param>
    /// <param name="aReverseRsaParameters">
    /// Set to true to read RSA modulus first. Normally exponent is read first.
    /// </param>
    /// <returns>AsymmetricKeyParameter containing the public key</returns>
    public AsymmetricKeyParameter ReadSsh1PublicKeyData(
      bool aReverseRsaParameters = false)
    {
      uint keyLength = ReadInt();
      var rsaN = new BigInteger(1, ReadSsh1BigIntBlob().Data);
      var rsaE = new BigInteger(1, ReadSsh1BigIntBlob().Data);

      if (aReverseRsaParameters) {
        return new RsaKeyParameters(false, rsaE, rsaN);
      }
      return new RsaKeyParameters(false, rsaN, rsaE);
    }


    /// <summary>
    /// reads private key portion of OpenSSH ssh1 formatted key blob from stream and
    /// creates a key pair
    /// </summary>
    /// <returns>key pair</returns>
    /// <remarks>
    /// intended to be called immediately after ParseSsh1PublicKeyData
    /// </remarks>
    public AsymmetricCipherKeyPair ReadSsh1KeyData(
      AsymmetricKeyParameter aPublicKeyParameter)
    {
      PinnedByteArray rsa_d = ReadSsh1BigIntBlob();
      PinnedByteArray rsa_iqmp = ReadSsh1BigIntBlob();
      PinnedByteArray rsa_q = ReadSsh1BigIntBlob();
      PinnedByteArray rsa_p = ReadSsh1BigIntBlob();

      var rsaD = new BigInteger(1, rsa_d.Data);
      var rsaIQMP = new BigInteger(1, rsa_iqmp.Data);
      var rsaP = new BigInteger(1, rsa_p.Data);
      var rsaQ = new BigInteger(1, rsa_q.Data);

      var rsaDP = rsaD.Remainder(rsaP.Subtract(BigInteger.One));
      var rsaDQ = rsaD.Remainder(rsaQ.Subtract(BigInteger.One));

      var rsaPublicKeyParams = aPublicKeyParameter as RsaKeyParameters;

      var rsaPrivateKeyParams = 
        new RsaPrivateCrtKeyParameters(rsaPublicKeyParams.Modulus,
          rsaPublicKeyParams.Exponent, rsaD, rsaP, rsaQ, rsaDP, rsaDQ, rsaIQMP);

      return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);
    }
  }
}
