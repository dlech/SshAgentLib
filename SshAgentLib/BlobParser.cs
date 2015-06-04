//
// BlobParser.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2015 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using dlech.SshAgentLib.Crypto;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// used to parse open-ssh blobs
  /// </summary>
  public class BlobParser
  {
    public Stream Stream { get; private set; }

    public BlobParser(byte[] blob) : this(new MemoryStream(blob)) { }

    public BlobParser(Stream stream)
    {
      if (stream == null) {
        throw new ArgumentNullException("stream");
      }
      Stream = stream;
    }

    public byte ReadByte()
    {
      if (Stream.CanSeek && Stream.Length - Stream.Position < 1) {
        throw new Exception("Not enough data");
      }
      return (byte)Stream.ReadByte();
    }

    public UInt32 ReadInt()
    {
      byte[] dataLegthBytes = new byte[4];
      if (Stream.CanSeek && Stream.Length - Stream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      return dataLegthBytes.ToInt();
    }

    public UInt16 ReadShort()
    {
        byte[] dataLegthBytes = new byte[2];
        if (Stream.CanSeek && Stream.Length - Stream.Position < dataLegthBytes.Length)
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
      if (Stream.CanSeek && Stream.Length - Stream.Position < header.BlobLength) {
        throw new Exception("Not enough data");
      }
      header.Message = (Agent.Message)ReadByte();
      return header;
    }

    public string ReadString()
    {
      return Encoding.UTF8.GetString(ReadBlob());
    }

    public byte[] ReadBlob()
    {
        return ReadBytes(ReadInt());
    }

    public byte[] ReadSsh1BigIntBlob()
    {
      var bitCount = ReadShort();
      return ReadBits(bitCount);
    }

    public byte[] ReadBits(UInt32 bitCount)
    {
      return ReadBytes((bitCount + (uint)7) / 8);
    }

    public byte[] ReadBytes(UInt32 blobLength)
    {
      if (Stream.CanSeek && Stream.Length - Stream.Position < blobLength)
        {
            throw new Exception("Not enough data");
        }
        var blob = new byte[(int)blobLength];
        Stream.Read(blob, 0, blob.Length);
        return blob;
    }


    /// <summary>
    /// reads OpenSSH formatted public key blob and creates
    /// an AsymmetricKeyParameter object
    /// </summary>
    /// <returns>AsymmetricKeyParameter containing the public key</returns>
    public AsymmetricKeyParameter ReadSsh2PublicKeyData()
    {
      var algorithm = Encoding.UTF8.GetString(ReadBlob());

      switch (algorithm) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY:
          var rsaN = new BigInteger(1, ReadBlob()); // modulus
          var rsaE = new BigInteger(1, ReadBlob()); // exponent
          if (rsaN.BitLength < rsaE.BitLength) {
            // In some cases, the modulus is first. We can always tell because
            // it is significantly larget than the exponent.
            return new RsaKeyParameters(false, rsaE, rsaN);
          }
          return new RsaKeyParameters(false, rsaN, rsaE);

        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY:
          var dsaP = new BigInteger(1, ReadBlob());
          var dsaQ = new BigInteger(1, ReadBlob());
          var dsaG = new BigInteger(1, ReadBlob());
          var dsaY = new BigInteger(1, ReadBlob()); // public key

          var dsaParams = new DsaParameters(dsaP, dsaQ, dsaG);
          return new DsaPublicKeyParameters(dsaY, dsaParams);

        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_KEY:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_KEY:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_KEY:

          var ecdsaCurveName = ReadString();
          var ecdsaPublicKey = ReadBlob();

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

        case PublicKeyAlgorithmExt.ALGORITHM_ED25519:
            var ed25519PublicKey = ReadBlob();
            return new Ed25519PublicKeyParameter(ed25519PublicKey);

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
      AsymmetricKeyParameter publicKeyParameter)
    {
      if (publicKeyParameter is RsaKeyParameters) {
        var rsaD = new BigInteger(1, ReadBlob());
        var rsaIQMP = new BigInteger(1, ReadBlob());
        var rsaP = new BigInteger(1, ReadBlob());
        var rsaQ = new BigInteger(1, ReadBlob());

        /* compute missing parameters */
        var rsaDP = rsaD.Remainder(rsaP.Subtract(BigInteger.One));
        var rsaDQ = rsaD.Remainder(rsaQ.Subtract(BigInteger.One));

        var rsaPublicKeyParams = publicKeyParameter as RsaKeyParameters;
        var rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
          rsaPublicKeyParams.Modulus, rsaPublicKeyParams.Exponent,
          rsaD, rsaP, rsaQ, rsaDP, rsaDQ, rsaIQMP);

        return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);
      } else if (publicKeyParameter is DsaPublicKeyParameters) {
        var dsaX = new BigInteger(1, ReadBlob()); // private key

        var dsaPublicKeyParams = publicKeyParameter as DsaPublicKeyParameters;
        DsaPrivateKeyParameters dsaPrivateKeyParams =
          new DsaPrivateKeyParameters(dsaX, dsaPublicKeyParams.Parameters);

        return new AsymmetricCipherKeyPair(dsaPublicKeyParams, dsaPrivateKeyParams);
      } else if (publicKeyParameter is ECPublicKeyParameters) {
        var ecdsaPrivate = new BigInteger(1, ReadBlob());

        var ecPublicKeyParams = publicKeyParameter as ECPublicKeyParameters;
        ECPrivateKeyParameters ecPrivateKeyParams =
          new ECPrivateKeyParameters(ecdsaPrivate, ecPublicKeyParams.Parameters);

        return new AsymmetricCipherKeyPair(ecPublicKeyParams, ecPrivateKeyParams);
      } else if (publicKeyParameter is Ed25519PublicKeyParameter) {
        var ed25519Signature = ReadBlob();
        var ed25519PrivateKey = new Ed25519PrivateKeyParameter(ed25519Signature);
        return new AsymmetricCipherKeyPair(publicKeyParameter, ed25519PrivateKey);
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
    /// <param name="reverseRsaParameters">
    /// Set to true to read RSA modulus first. Normally exponent is read first.
    /// </param>
    /// <returns>AsymmetricKeyParameter containing the public key</returns>
    public AsymmetricKeyParameter ReadSsh1PublicKeyData(
      bool reverseRsaParameters = false)
    {
      // ignore not used warning
      #pragma warning disable 0219
      uint keyLength = ReadInt();
      #pragma warning restore 0219
      var rsaN = new BigInteger(1, ReadSsh1BigIntBlob());
      var rsaE = new BigInteger(1, ReadSsh1BigIntBlob());

      if (reverseRsaParameters) {
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
      AsymmetricKeyParameter publicKeyParameter)
    {
      var rsa_d = ReadSsh1BigIntBlob();
      var rsa_iqmp = ReadSsh1BigIntBlob();
      var rsa_q = ReadSsh1BigIntBlob();
      var rsa_p = ReadSsh1BigIntBlob();

      var rsaD = new BigInteger(1, rsa_d);
      var rsaIQMP = new BigInteger(1, rsa_iqmp);
      var rsaP = new BigInteger(1, rsa_p);
      var rsaQ = new BigInteger(1, rsa_q);

      var rsaDP = rsaD.Remainder(rsaP.Subtract(BigInteger.One));
      var rsaDQ = rsaD.Remainder(rsaQ.Subtract(BigInteger.One));

      var rsaPublicKeyParams = publicKeyParameter as RsaKeyParameters;

      var rsaPrivateKeyParams = 
        new RsaPrivateCrtKeyParameters(rsaPublicKeyParams.Modulus,
          rsaPublicKeyParams.Exponent, rsaD, rsaP, rsaQ, rsaDP, rsaDQ, rsaIQMP);

      return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);
    }
  }
}
