//
// BlobParser.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2015,2017 David Lechner
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
using System.Collections.Generic;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// used to parse open-ssh blobs
  /// </summary>
  public class BlobParser
  {
    static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public Stream Stream { get; private set; }
    public long Position { get; private set; }

    public BlobParser(byte[] blob) : this(new MemoryStream(blob)) { }

    public BlobParser(Stream stream)
    {
      if (stream == null) {
        throw new ArgumentNullException("stream");
      }
      Position = 0;
      Stream = stream;
    }

    public byte ReadUInt8()
    {
      if (Stream.CanSeek && Stream.Length - Stream.Position < 1) {
        throw new Exception("Not enough data");
      }
      Position += 1;
      return (byte)Stream.ReadByte();
    }

    public ushort ReadUInt16()
    {
        byte[] dataLegthBytes = new byte[2];
        if (Stream.CanSeek && Stream.Length - Stream.Position < dataLegthBytes.Length)
        {
            throw new Exception("Not enough data");
        }
        Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
        Position += dataLegthBytes.Length;
        return (ushort)((dataLegthBytes[0] << 8) | dataLegthBytes[1]);
    }

    public uint ReadUInt32()
    {
      byte[] dataLegthBytes = new byte[4];
      if (Stream.CanSeek && Stream.Length - Stream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      Position += dataLegthBytes.Length;
      return (uint)((dataLegthBytes[0] << 24) | (dataLegthBytes[1] << 16) | (dataLegthBytes[2] << 8) | dataLegthBytes[3]);
    }

    public ulong ReadUInt64()
    {
      byte[] dataLegthBytes = new byte[8];
      if (Stream.CanSeek && Stream.Length - Stream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      Position += dataLegthBytes.Length;
      return (ulong)((dataLegthBytes[0] << 56) | (dataLegthBytes[1] << 48) | (dataLegthBytes[2] << 40) | (dataLegthBytes[3] << 32)
                     + (dataLegthBytes[4] << 24) | (dataLegthBytes[5] << 16) | (dataLegthBytes[6] << 8) | dataLegthBytes[7]);
    }

    public Agent.BlobHeader ReadHeader()
    {
      Agent.BlobHeader header = new Agent.BlobHeader();

      header.BlobLength = ReadUInt32();
      if (Stream.CanSeek && Stream.Length - Stream.Position < header.BlobLength) {
        throw new Exception("Not enough data");
      }
      header.Message = (Agent.Message)ReadUInt8();
      return header;
    }

    public string ReadString()
    {
      return Encoding.UTF8.GetString(ReadBlob());
    }

    public byte[] ReadBlob()
    {
        uint blobLength = ReadUInt32();
        return ReadBytes(blobLength);
    }

    public byte[] ReadSsh1BigIntBlob()
    {
      var bitCount = ReadUInt16();
      return ReadBits(bitCount);
    }

    public byte[] ReadBits(uint bitCount)
    {
      return ReadBytes((bitCount + 7) / 8);
    }

    public byte[] ReadBytes(uint blobLength)
    {
      if (Stream.CanSeek && Stream.Length - Stream.Position < blobLength)
        {
            throw new Exception("Not enough data");
        }
        var blob = new byte[(int)blobLength];
        Stream.Read(blob, 0, blob.Length);
        Position += blob.Length;
        return blob;
    }

    OpensshCertificate ReadCertificate(BlobBuilder builder)
    {
      var serial = ReadUInt64();
      builder.AddUInt64(serial);
      var type = (Ssh2CertType)ReadUInt32();
      builder.AddUInt32((uint)type);
      var keyId = ReadString();
      builder.AddStringBlob(keyId);
      var validPrincipals = ReadBlob();
      builder.AddBlob(validPrincipals);
      var validAfter = ReadUInt64();
      builder.AddUInt64(validAfter);
      var validBefore = ReadUInt64();
      builder.AddUInt64(validBefore);
      var criticalOptions = ReadBlob();
      builder.AddBlob(criticalOptions);
      var extensions = ReadBlob();
      builder.AddBlob(extensions);
      var reserved = ReadBlob();
      builder.AddBlob(reserved);
      var signatureKey = ReadBlob();
      builder.AddBlob(signatureKey);
      var signature = ReadBlob();
      builder.AddBlob(signature);

      var principalsParser = new BlobParser(validPrincipals);
      var principalsList = new List<string>();
      while (principalsParser.Stream.Position < principalsParser.Stream.Length) {
        principalsList.Add(principalsParser.ReadString());
      }
      var validAfterDateTime = validAfter == ulong.MaxValue ? DateTime.MaxValue : epoch.AddSeconds(validAfter);
      var validBeforeDateTime = validBefore == ulong.MaxValue ? DateTime.MaxValue : epoch.AddSeconds(validBefore);
      var signatureKeyParser = new BlobParser(signatureKey);
      OpensshCertificate unused;
      var sigKey = signatureKeyParser.ReadSsh2PublicKeyData(out unused);

      return new OpensshCertificate(builder.GetBlob(), type, serial, keyId,
                                    principalsList, validAfterDateTime,
                                    validBeforeDateTime, criticalOptions,
                                    extensions, sigKey);
    }

    /// <summary>
    /// reads OpenSSH formatted public key blob and creates
    /// an AsymmetricKeyParameter object
    /// </summary>
    /// <returns>AsymmetricKeyParameter containing the public key</returns>
    public AsymmetricKeyParameter ReadSsh2PublicKeyData(out OpensshCertificate cert)
    {
      cert = null;
      var algorithm = Encoding.UTF8.GetString(ReadBlob());
      var certBuilder = new BlobBuilder();
      certBuilder.AddStringBlob(algorithm);

      switch (algorithm) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY: {
          var n = new BigInteger(1, ReadBlob()); // modulus
          var e = new BigInteger(1, ReadBlob()); // exponent
          if (n.BitLength < e.BitLength) {
            // In some cases, the modulus is first. We can always tell because
            // it is significantly larget than the exponent.
            return new RsaKeyParameters(false, e, n);
          }
          return new RsaKeyParameters(false, n, e);
        }

        case PublicKeyAlgorithmExt.ALGORITHM_RSA_CERT_V1: {
          var nonce = ReadBlob ();
          if (nonce.Length != 32) {
            // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
            // is the whole certificate, not the nonce
            var certParser = new BlobParser (nonce);
            return certParser.ReadSsh2PublicKeyData (out cert);
          } else {
            certBuilder.AddBlob (nonce);
            var e = new BigInteger (1, ReadBlob ());
            certBuilder.AddBigIntBlob (e);
            var n = new BigInteger (1, ReadBlob ());
            certBuilder.AddBigIntBlob (n);

            cert = ReadCertificate (certBuilder);

            return new RsaKeyParameters (false, n, e);
          }
        }

        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY: {
          var p = new BigInteger(1, ReadBlob());
          var q = new BigInteger(1, ReadBlob());
          var g = new BigInteger(1, ReadBlob());
          var y = new BigInteger(1, ReadBlob());

          var dsaParams = new DsaParameters(p, q, g);
          return new DsaPublicKeyParameters(y, dsaParams);
        }

        case PublicKeyAlgorithmExt.ALGORITHM_DSA_CERT_V1: {
          var nonce = ReadBlob();
          if (nonce.Length != 32) {
            // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
            // is the whole certificate, not the nonce
            var certParser = new BlobParser (nonce);
            return certParser.ReadSsh2PublicKeyData (out cert);
          } else {
            certBuilder.AddBlob (nonce);
            var p = new BigInteger (1, ReadBlob ());
            certBuilder.AddBigIntBlob (p);
            var q = new BigInteger (1, ReadBlob ());
            certBuilder.AddBigIntBlob (q);
            var g = new BigInteger (1, ReadBlob ());
            certBuilder.AddBigIntBlob (g);
            var y = new BigInteger (1, ReadBlob ());
            certBuilder.AddBigIntBlob (y);

            cert = ReadCertificate (certBuilder);

            var dsaParams = new DsaParameters (p, q, g);
            return new DsaPublicKeyParameters(y, dsaParams);
          }
        }

        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_KEY:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_KEY:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_KEY: {
          var curveName = ReadString();
          var publicKey = ReadBlob();

          var x9Params = SecNamedCurves.GetByName(EcCurveToAlgorithm (curveName));
          var domainParams = new ECDomainParameters(x9Params.Curve, x9Params.G, x9Params.N, x9Params.H);
          var point = x9Params.Curve.DecodePoint(publicKey);
          return new ECPublicKeyParameters(point, domainParams);
        }

        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_CERT_V1:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_CERT_V1:
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_CERT_V1: {
          var nonce = ReadBlob();
          if (nonce.Length != 32) {
            // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
            // is the whole certificate, not the nonce
            var certParser = new BlobParser (nonce);
            return certParser.ReadSsh2PublicKeyData (out cert);
          } else {
            certBuilder.AddBlob (nonce);
            var curveName = ReadString ();
            certBuilder.AddStringBlob (curveName);
            var publicKey = ReadBlob ();
            certBuilder.AddBlob (publicKey);

            cert = ReadCertificate (certBuilder);

            var x9Params = SecNamedCurves.GetByName (EcCurveToAlgorithm (curveName));
            var domainParams = new ECDomainParameters (x9Params.Curve, x9Params.G, x9Params.N, x9Params.H);
            var point = x9Params.Curve.DecodePoint (publicKey);

            return new ECPublicKeyParameters (point, domainParams);
          }
        }

        case PublicKeyAlgorithmExt.ALGORITHM_ED25519: {
          var publicKey = ReadBlob();
          return new Ed25519PublicKeyParameter(publicKey);
        }

        case PublicKeyAlgorithmExt.ALGORITHM_ED25519_CERT_V1: {
          var nonce = ReadBlob();
          if (nonce.Length != 32) {
            // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
            // is the whole certificate, not the nonce
            var certParser = new BlobParser (nonce);
            certParser.ReadSsh2PublicKeyData (out cert);
            var publicKey = ReadBlob ();

            return new Ed25519PublicKeyParameter (publicKey);
          } else {
            certBuilder.AddBlob (nonce);
            var publicKey = ReadBlob ();
            certBuilder.AddBlob (publicKey);

            cert = ReadCertificate (certBuilder);

            return new Ed25519PublicKeyParameter (publicKey);
          }
        }

        default:
          // unsupported encryption algorithm
          throw new Exception("Unsupported algorithm");
      }
    }

    /// <summary>
    /// Convert the Openssh curve name to the BouncyCastle curve name
    /// </summary>
    static string EcCurveToAlgorithm(string name)
    {
      switch (name) {
      case PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP256:
        return "secp256r1";
      case PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP384:
        return "secp384r1";
      case PublicKeyAlgorithmExt.EC_ALGORITHM_NISTP521:
        return "secp521r1";
      default:
        throw new ArgumentException ("Unsupported EC algorithm: " + name, "name");
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
      uint keyLength = ReadUInt32();
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
