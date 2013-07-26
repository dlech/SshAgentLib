//
// ISshKey.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013 David Lechner
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
    /// <param name="Algorithm">AsymmetricAlgorithm to convert.</param>
    /// <returns>byte array containing key information</returns>
    /// <exception cref="ArgumentException">
    /// AsymmetricAlgorithm is not supported
    /// </exception>
    /// <remarks>
    /// Currently only supports RSA and DSA public keys
    /// </remarks>
    public static byte[] GetPublicKeyBlob(this ISshKey aKey)
    {
      AsymmetricKeyParameter parameters = aKey.GetPublicKeyParameters();
      BlobBuilder builder = new BlobBuilder();
      if (parameters is RsaKeyParameters) {
        RsaKeyParameters rsaPublicKeyParameters = (RsaKeyParameters)parameters;
        if (aKey.Version == SshVersion.SSH1) {
          builder.AddInt(aKey.Size);
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
      } else {
        throw new ArgumentException(parameters.GetType() + " is not supported");
      }
      byte[] result = builder.GetBlob();
      builder.Clear();
      return result;
    }

    public static byte[] GetMD5Fingerprint(this ISshKey aKey)
    {
      try {
        using (MD5 md5 = MD5.Create()) {
          if (aKey.GetPublicKeyParameters() is RsaKeyParameters && aKey.Version == SshVersion.SSH1) {
            var rsaKeyParameters = aKey.GetPublicKeyParameters() as RsaKeyParameters;

            int modSize = rsaKeyParameters.Modulus.ToByteArrayUnsigned().Length;
            int expSize = rsaKeyParameters.Exponent.ToByteArrayUnsigned().Length;
            byte[] md5Buffer = new byte[modSize + expSize];

            rsaKeyParameters.Modulus.ToByteArrayUnsigned().CopyTo(md5Buffer, 0);
            rsaKeyParameters.Exponent.ToByteArrayUnsigned().CopyTo(md5Buffer, modSize);

            return md5.ComputeHash(md5Buffer);
          }

          return md5.ComputeHash(aKey.GetPublicKeyBlob());
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

    public static byte[] FormatSignature(this ISshKey aKey, byte[] aSignature)
    {
      AsymmetricKeyParameter publicKey = aKey.GetPublicKeyParameters();
      if (publicKey is DsaPublicKeyParameters ||
        publicKey is ECPublicKeyParameters) {
        Asn1Sequence seq = (Asn1Sequence)Asn1Object.FromByteArray(aSignature);
        BigInteger r = ((DerInteger)seq[0]).PositiveValue;
        BigInteger s = ((DerInteger)seq[1]).PositiveValue;
        BlobBuilder formatedSignature = new BlobBuilder();
        if (publicKey is ECPublicKeyParameters) {
          formatedSignature.AddBlob(r.ToByteArray());
          formatedSignature.AddBlob(s.ToByteArray());
        } else {
          formatedSignature.AddBytes(r.ToByteArrayUnsigned());
          formatedSignature.AddBytes(s.ToByteArrayUnsigned());
        }
        return formatedSignature.GetBlob();
      } else if (publicKey is RsaKeyParameters) {
        return aSignature;
      }
      throw new Exception("Unsupported algorithm");
    }

    public static ISigner GetSigner(this ISshKey aKey)
    {
      AsymmetricKeyParameter publicKey = aKey.GetPublicKeyParameters();
      if (publicKey is DsaPublicKeyParameters) {
        return SignerUtilities.GetSigner(X9ObjectIdentifiers.IdDsaWithSha1);
      } else if (publicKey is RsaKeyParameters) {
        return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
      } else if (publicKey is ECPublicKeyParameters) {
        int ecdsaFieldSize =
         ((ECPublicKeyParameters)publicKey).Q.Curve.FieldSize;
        if (ecdsaFieldSize <= 256) {
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha256);
        } else if (ecdsaFieldSize > 256 && ecdsaFieldSize <= 384) {
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha384);
        } else if (ecdsaFieldSize > 384) {
          return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha512);
        }
      }
      throw new Exception("Unsupported algorithm");
    }
  }
}
