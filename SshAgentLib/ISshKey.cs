//
// ISshKey.cs
//
// Author(s): David Lechner <david@lechnology.com>
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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using dlech.SshAgentLib.Crypto;
using SignRequestFlags = dlech.SshAgentLib.Agent.SignRequestFlags;

namespace dlech.SshAgentLib
{
  public interface ISshKey : IDisposable
  {
    /// <summary>
    /// The SSH protocol version
    /// </summary>
    SshVersion Version { get; }

    /// <summary>
    /// The public key algorithm
    /// </summary>
    PublicKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// The certificate for signed keys or <c>null</c> for unsigned keys
    /// </summary>
    OpensshCertificate Certificate { get; }

    /// <summary>
    /// returns true if key does not have private key parameters
    /// </summary>
    bool IsPublicOnly { get; }

    /// <summary>
    /// The bit size of the key
    /// </summary>
    int Size { get; }

    /// <summary>
    /// Comment associated with key
    /// </summary>
    string Comment { get; set; }

    /// <summary>
    /// The source of the key file. Usually a file path.
    /// </summary>
    string Source { get; set; }

    /// <summary>
    /// List of key constraints applied to this key
    /// </summary>
    ReadOnlyCollection<Agent.KeyConstraint> Constraints { get; }

    /// <summary>
    /// Gets a copy of the public key parameters
    /// </summary>
    /// <returns></returns>
    AsymmetricKeyParameter GetPublicKeyParameters();

    /// <summary>
    /// Gets a copy of the private key parameters
    /// </summary>
    /// <returns></returns>
    AsymmetricKeyParameter GetPrivateKeyParameters();

    /// <summary>
    /// Add constraint to key
    /// </summary>
    /// <param name="aConstraint"></param>
    void AddConstraint(Agent.KeyConstraint aConstraint);
  }

  public static class ISshKeyExt
  {
    /// <summary>
    /// Adds Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM constraint to key
    /// </summary>
    public static void addConfirmConstraint(this ISshKey aKey)
    {
      var constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
      aKey.AddConstraint(constraint);
    }

    /// <summary>
    /// Adds Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME constraint to key
    /// </summary>
    public static void addLifetimeConstraint(this ISshKey aKey, uint aLifetime)
    {
      var constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
      constraint.Data = aLifetime;
      aKey.AddConstraint(constraint);
    }

    public static ISshKey Get(this ICollection<ISshKey> aKeyList,
      SshVersion aVersion,
      byte[] aPublicKeyBlob)
    {
      foreach (ISshKey key in aKeyList.Where(key => key.Version == aVersion)) {
        byte[] keyBlob = key.GetPublicKeyBlob();
        if (keyBlob.SequenceEqual(aPublicKeyBlob)) {
          return key;
        }
      }
      return null;
    }

    /// <summary>
    /// Gets OpenSsh formatted bytes from public key
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cert">When set to <c>true</c> and the key has a certificate, the certificate blob will be used.</param>
    /// <returns>byte array containing key information</returns>
    public static byte[] GetPublicKeyBlob(this ISshKey key, bool cert = true)
    {
      if (cert && key.Certificate != null) {
        return key.Certificate.Blob;
      }
      AsymmetricKeyParameter parameters = key.GetPublicKeyParameters();
      BlobBuilder builder = new BlobBuilder();
      if (parameters is RsaKeyParameters) {
        RsaKeyParameters rsaPublicKeyParameters = (RsaKeyParameters)parameters;
        if (key.Version == SshVersion.SSH1) {
          builder.AddInt(key.Size);
          builder.AddSsh1BigIntBlob(rsaPublicKeyParameters.Exponent);
          builder.AddSsh1BigIntBlob(rsaPublicKeyParameters.Modulus);
        } else {
          builder.AddStringBlob(PublicKeyAlgorithm.SSH_RSA.GetIdentifierString());
          builder.AddBigIntBlob(rsaPublicKeyParameters.Exponent);
          builder.AddBigIntBlob(rsaPublicKeyParameters.Modulus);
        }
      } else if (parameters is DsaPublicKeyParameters) {
        DsaPublicKeyParameters dsaParameters =
          (DsaPublicKeyParameters)parameters;

        builder.AddStringBlob(PublicKeyAlgorithm.SSH_DSS.GetIdentifierString());
        builder.AddBigIntBlob(dsaParameters.Parameters.P);
        builder.AddBigIntBlob(dsaParameters.Parameters.Q);
        builder.AddBigIntBlob(dsaParameters.Parameters.G);
        builder.AddBigIntBlob(dsaParameters.Y);
      } else if (parameters is ECPublicKeyParameters) {
        ECPublicKeyParameters ecdsaParameters =
          (ECPublicKeyParameters)parameters;

        string algorithm;
        switch (ecdsaParameters.Parameters.Curve.FieldSize) {
          case 256:
            algorithm = PublicKeyAlgorithm.ECDSA_SHA2_NISTP256.GetIdentifierString();
            break;
          case 384:
            algorithm = PublicKeyAlgorithm.ECDSA_SHA2_NISTP384.GetIdentifierString();
            break;
          case 521:
            algorithm = PublicKeyAlgorithm.ECDSA_SHA2_NISTP521.GetIdentifierString();
            break;
          default:
            throw new ArgumentException("Unsupported EC size: " +
              ecdsaParameters.Parameters.Curve.FieldSize);
        }
        builder.AddStringBlob(algorithm);
        algorithm =
          algorithm.Replace(PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_PREFIX,
          string.Empty);
        builder.AddStringBlob(algorithm);
        builder.AddBlob(ecdsaParameters.Q.GetEncoded());
      } else if (parameters is Ed25519PublicKeyParameter) {
          builder.AddStringBlob(PublicKeyAlgorithm.ED25519.GetIdentifierString());
          builder.AddBlob(((Ed25519PublicKeyParameter)parameters).Key);
      } else {
        throw new ArgumentException(parameters.GetType() + " is not supported");
      }
      byte[] result = builder.GetBlob();
      builder.Clear();
      return result;
    }

    public static string GetAuthorizedKeyString(this ISshKey aKey)
    {
      string result = "";
      switch (aKey.Version) {
        case SshVersion.SSH1:
          AsymmetricKeyParameter parameters = aKey.GetPublicKeyParameters();
          RsaKeyParameters rsaPublicKeyParameters = (RsaKeyParameters)parameters;
          result = aKey.Size + " " +
            rsaPublicKeyParameters.Exponent.ToString(10) + " " +
            rsaPublicKeyParameters.Modulus.ToString(10) + " " +
            String.Format(aKey.GetMD5Fingerprint().ToHexString()) + " " +
            aKey.Comment;
          break;
        case SshVersion.SSH2:
          result = PublicKeyAlgorithmExt.GetIdentifierString(aKey.Algorithm)+ " " +
            Convert.ToBase64String(aKey.GetPublicKeyBlob()) + " " +
            String.Format(aKey.GetMD5Fingerprint().ToHexString()) + " " +
            aKey.Comment;
          break;
        default:
          result = "# unsuported SshVersion: '"+aKey.Version+"'";
          break;
      }
      return result;
    }

    public static byte[] GetMD5Fingerprint(this ISshKey key)
    {
      try {
        using (MD5 md5 = MD5.Create()) {
          if (key.GetPublicKeyParameters() is RsaKeyParameters && key.Version == SshVersion.SSH1) {
            var rsaKeyParameters = key.GetPublicKeyParameters() as RsaKeyParameters;

            int modSize = rsaKeyParameters.Modulus.ToByteArrayUnsigned().Length;
            int expSize = rsaKeyParameters.Exponent.ToByteArrayUnsigned().Length;
            byte[] md5Buffer = new byte[modSize + expSize];

            rsaKeyParameters.Modulus.ToByteArrayUnsigned().CopyTo(md5Buffer, 0);
            rsaKeyParameters.Exponent.ToByteArrayUnsigned().CopyTo(md5Buffer, modSize);

            return md5.ComputeHash(md5Buffer);
          }

          return md5.ComputeHash(key.GetPublicKeyBlob(false));
        }
      } catch (Exception) {
        return null;
      }
    }

    public static bool HasConstraint(this ISshKey aKey,
      Agent.KeyConstraintType aType)
    {
      return aKey.Constraints.Count(c => c.Type == aType) > 0;
    }

    public static byte[] FormatSignature(this ISshKey key, byte[] signature)
    {
      AsymmetricKeyParameter publicKey = key.GetPublicKeyParameters();
      if (publicKey is DsaPublicKeyParameters ||
        publicKey is ECPublicKeyParameters) {
        Asn1Sequence seq = (Asn1Sequence)Asn1Object.FromByteArray(signature);
        BigInteger r = ((DerInteger)seq[0]).PositiveValue;
        BigInteger s = ((DerInteger)seq[1]).PositiveValue;
        BlobBuilder formatedSignature = new BlobBuilder();
        if (publicKey is ECPublicKeyParameters) {
          var bytes = r.ToByteArray().ToList ();
          while (bytes.Count < 20)
            bytes.Insert(0, 0);
          formatedSignature.AddBlob(bytes.ToArray());
          bytes = s.ToByteArray().ToList();
          while (bytes.Count < 20)
            bytes.Insert(0, 0);
          formatedSignature.AddBlob(bytes.ToArray());
        } else {
          var bytes = r.ToByteArrayUnsigned().ToList();
          while (bytes.Count < 20)
            bytes.Insert(0, 0);
          formatedSignature.AddBytes(bytes.ToArray());
          bytes = s.ToByteArrayUnsigned().ToList();
          while (bytes.Count < 20)
            bytes.Insert(0, 0);
          formatedSignature.AddBytes(bytes.ToArray());
        }
        return formatedSignature.GetBlob();
      } else if (publicKey is RsaKeyParameters || publicKey is Ed25519PublicKeyParameter) {
        return signature;
      }
      throw new Exception("Unsupported algorithm");
    }

    /// <summary>
    /// Get a signer for a key. The algorithm is determined by the type of the
    /// key and in the case of RSA keys, the optional flags.
    /// </summary>
    /// <param name="key">A SSH key</param>
    /// <param name="flags">Optional flags</param>
    /// <returns>A Signer</returns>
    public static ISigner GetSigner(this ISshKey key, SignRequestFlags flags = default(SignRequestFlags))
    {
      var publicKey = key.GetPublicKeyParameters();

      if (publicKey is DsaPublicKeyParameters) {
        return SignerUtilities.GetSigner(X9ObjectIdentifiers.IdDsaWithSha1);
      }
      else if (publicKey is RsaKeyParameters) {
        // flags can influence hash type for RSA keys

        if (flags.HasFlag(SignRequestFlags.SSH_AGENT_RSA_SHA2_512)) {
          return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha512WithRsaEncryption);
        }

        if (flags.HasFlag(SignRequestFlags.SSH_AGENT_RSA_SHA2_256)) {
          return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
        }

        return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
      }
      else if (publicKey is ECPublicKeyParameters) {
        var ecdsaFieldSize = ((ECPublicKeyParameters)publicKey).Q.Curve.FieldSize;
        
        if (ecdsaFieldSize <= 256) {
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha256);
        }
        else if (ecdsaFieldSize > 256 && ecdsaFieldSize <= 384) {
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha384);
        }
        else if (ecdsaFieldSize > 384) {
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha512);
        }
      }
      else if (publicKey is Ed25519PublicKeyParameter) {
          return new Ed25519Signer();
      }

      throw new ArgumentException("Unsupported algorithm", "key");
    }
  }
}
