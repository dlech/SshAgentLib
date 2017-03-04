//
// SshKey.cs
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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using dlech.SshAgentLib.Crypto;
using Chaos.NaCl;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Class for encapsulating information on encryption keys so that it can be
  /// used in PuTTY related programs
  /// </summary>
  public class SshKey : ISshKey
  {
    private List<Agent.KeyConstraint> keyConstraints;
    private AsymmetricKeyParameter publicKeyParameter;
    private AsymmetricKeyParameter privateKeyParameter;

    public SshKey(SshVersion version, AsymmetricKeyParameter publicKeyParameter,
      AsymmetricKeyParameter privateKeyParameter = null, string comment = "",
      OpensshCertificate certificate = null)
    {
      if (publicKeyParameter == null) {
        throw new ArgumentNullException("publicKeyParameter");
      }
      IsPublicOnly = (privateKeyParameter == null);
      Version = version;
      this.publicKeyParameter = publicKeyParameter;
      this.privateKeyParameter = privateKeyParameter;
      Certificate = certificate;
      Comment = comment;
      keyConstraints = new List<Agent.KeyConstraint>();
    }

    public SshKey(SshVersion version, AsymmetricCipherKeyPair cipherKeyPair,
                  string comment = "", OpensshCertificate certificate = null)
      : this(version, cipherKeyPair.Public, cipherKeyPair.Private, comment, certificate)
    {
    }
    
    public SshVersion Version { get; private set; }

    public PublicKeyAlgorithm Algorithm
    {
      get
      {
        if (publicKeyParameter is RsaKeyParameters) {
          if (Certificate != null) {
            return PublicKeyAlgorithm.SSH_RSA_CERT_V1;
          }
          return PublicKeyAlgorithm.SSH_RSA;
        } else if (publicKeyParameter is DsaPublicKeyParameters) {
          if (Certificate != null) {
            return PublicKeyAlgorithm.SSH_DSS_CERT_V1;
          }
          return PublicKeyAlgorithm.SSH_DSS;
        } else if (publicKeyParameter is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)publicKeyParameter;
          switch (ecdsaParameters.Q.Curve.FieldSize) {
            case 256:
              if (Certificate != null) {
                return PublicKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V1;
              }
              return PublicKeyAlgorithm.ECDSA_SHA2_NISTP256;
            case 384:
              if (Certificate != null) {
                return PublicKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V1;
              }
              return PublicKeyAlgorithm.ECDSA_SHA2_NISTP384;
            case 521:
              if (Certificate != null) {
                return PublicKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V1;
              }
              return PublicKeyAlgorithm.ECDSA_SHA2_NISTP521;
          }
        } else if (publicKeyParameter is Ed25519PublicKeyParameter) {
          if (Certificate != null) {
            return PublicKeyAlgorithm.ED25519_CERT_V1;
          }
           return PublicKeyAlgorithm.ED25519;
        }
        throw new Exception("Unknown algorithm");
      }
    }

    public OpensshCertificate Certificate { get; private set; }

    public bool IsPublicOnly { get; private set; }

    public int Size
    {
      get
      {
        if (publicKeyParameter is RsaKeyParameters) {
          RsaKeyParameters rsaKeyParameters =
            (RsaKeyParameters)publicKeyParameter;
          return rsaKeyParameters.Modulus.BitLength;
        } else if (publicKeyParameter is DsaPublicKeyParameters) {
          DsaPublicKeyParameters dsaKeyParameters =
            (DsaPublicKeyParameters)publicKeyParameter;
          return dsaKeyParameters.Parameters.P.BitLength;
        } else if (publicKeyParameter is ECPublicKeyParameters) {
          ECPublicKeyParameters ecdsaParameters =
            (ECPublicKeyParameters)publicKeyParameter;
          return ecdsaParameters.Q.Curve.FieldSize;
        } else if (publicKeyParameter is Ed25519PublicKeyParameter) {
            return Ed25519.PublicKeySizeInBytes * 8;
        }
        // TODO need a better exception here
        throw new Exception("Not Defined");
      }
    }
    
    /// <summary>
    /// User comment
    /// </summary>
    public string Comment { get; set; }

    /// <summary>
    /// Source of the key file
    /// </summary>
    public string Source { get; set; }

    public ReadOnlyCollection<Agent.KeyConstraint> Constraints
    {
      get
      {
        return keyConstraints.AsReadOnly();
      }
    }

    public AsymmetricKeyParameter GetPublicKeyParameters()
    {
      return publicKeyParameter;
    }

    public AsymmetricKeyParameter GetPrivateKeyParameters()
    {
      return privateKeyParameter;
    }

    public void AddConstraint(Agent.KeyConstraint aConstraint)
    {
      if ((aConstraint.Data == null && aConstraint.Type.GetDataType() != null) ||
          (aConstraint.Data != null &&
           aConstraint.Data.GetType() != aConstraint.Type.GetDataType())) {
        throw new ArgumentException("Malformed constraint", "aConstraint");
      }
      keyConstraints.Add(aConstraint);
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
      newKey.Source = Source;
      foreach (Agent.KeyConstraint constraint in keyConstraints) {
        newKey.AddConstraint(constraint);
      }
      return newKey;
    }
  }
}
