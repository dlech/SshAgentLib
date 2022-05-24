//
// ISshKey.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2015,2017,2022 David Lechner
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
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using SshAgentLib.Keys;
using SignRequestFlags = dlech.SshAgentLib.Agent.SignRequestFlags;

namespace dlech.SshAgentLib
{
    public interface ISshKey : IDisposable
    {
        /// <summary>
        /// The public key algorithm
        /// </summary>
        PublicKeyAlgorithm Algorithm { get; }

        /// <summary>
        /// The nonce for signed keys or <c>null</c> for unsigned keys
        /// </summary>
        byte[] Nonce { get; }

        /// <summary>
        /// The certificate for signed keys or <c>null</c> for unsigned keys
        /// </summary>
        OpensshCertificateInfo Certificate { get; }

        /// <summary>
        /// Gets the application for keys associated with a hardware key or
        /// <c>null</c> for keys that are not associated with a hardware key.
        /// </summary>
        string Application { get; }

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

        public static ISshKey TryGet(this ICollection<ISshKey> keyList, byte[] publicKeyBlob)
        {
            foreach (var key in keyList)
            {
                var keyBlob = key.GetPublicKeyBlob();

                if (keyBlob.SequenceEqual(publicKeyBlob))
                {
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
            var parameters = key.GetPublicKeyParameters();
            var builder = new BlobBuilder();

            if (cert)
            {
                builder.AddStringBlob(key.Algorithm.GetIdentifier());
            }
            else
            {
                builder.AddStringBlob(
                    key.Algorithm.GetIdentifier().Replace("-cert-v01@openssh.com", "")
                );
            }

            if (cert && key.Certificate != null)
            {
                builder.AddBlob(key.Nonce);
            }

            if (parameters is RsaKeyParameters rsaPublicKeyParameters)
            {
                builder.AddBigIntBlob(rsaPublicKeyParameters.Exponent);
                builder.AddBigIntBlob(rsaPublicKeyParameters.Modulus);
            }
            else if (parameters is DsaPublicKeyParameters dsaParameters)
            {
                builder.AddBigIntBlob(dsaParameters.Parameters.P);
                builder.AddBigIntBlob(dsaParameters.Parameters.Q);
                builder.AddBigIntBlob(dsaParameters.Parameters.G);
                builder.AddBigIntBlob(dsaParameters.Y);
            }
            else if (parameters is ECPublicKeyParameters ecdsaParameters)
            {
                builder.AddStringBlob(key.Algorithm.GetCurveDomainIdentifier());
                builder.AddBlob(ecdsaParameters.Q.GetEncoded());
            }
            else if (parameters is Ed25519PublicKeyParameters ed15519Parameters)
            {
                builder.AddBlob(ed15519Parameters.GetEncoded());
            }
            else
            {
                throw new ArgumentException(
                    $"{parameters.GetType()} is not a supported algorithm",
                    nameof(key)
                );
            }

            if (key.Application != null)
            {
                builder.AddStringBlob(key.Application);
            }

            if (cert && key.Certificate != null)
            {
                var principalsBuilder = new BlobBuilder();

                foreach (var p in key.Certificate.Principals)
                {
                    principalsBuilder.AddStringBlob(p);
                }

                builder.AddUInt64(key.Certificate.Serial);
                builder.AddUInt32((uint)key.Certificate.Type);
                builder.AddStringBlob(key.Certificate.KeyId);
                builder.AddBlob(principalsBuilder.GetBlob());
                builder.AddUInt64(key.Certificate.ValidAfter);
                builder.AddUInt64(key.Certificate.ValidBefore);
                builder.AddBlob(key.Certificate.CriticalOptions);
                builder.AddBlob(key.Certificate.Extensions);
                builder.AddBlob(key.Certificate.Reserved);
                builder.AddBlob(key.Certificate.SignatureKey.KeyBlob);
                builder.AddBlob(key.Certificate.Signature);
            }

            var result = builder.GetBlob();

            return result;
        }

        public static string GetAuthorizedKeyString(this ISshKey key)
        {
            return $"{key.Algorithm.GetIdentifier()} {Convert.ToBase64String(key.GetPublicKeyBlob())} {key.Comment}";
        }

        public static byte[] GetMD5Fingerprint(this ISshKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(key.GetPublicKeyBlob(false));
            }
        }

        public static string GetSha256Fingerprint(this ISshKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(key.GetPublicKeyBlob());
                return $"SHA256:{Convert.ToBase64String(hash).Trim('=')}";
            }
        }

        public static bool HasConstraint(this ISshKey aKey, Agent.KeyConstraintType aType)
        {
            return aKey.Constraints.Count(c => c.Type == aType) > 0;
        }

        public static byte[] FormatSignature(this ISshKey key, byte[] signature)
        {
            var publicKey = key.GetPublicKeyParameters();
            if (publicKey is DsaPublicKeyParameters || publicKey is ECPublicKeyParameters)
            {
                var seq = (Asn1Sequence)Asn1Object.FromByteArray(signature);
                var r = ((DerInteger)seq[0]).PositiveValue;
                var s = ((DerInteger)seq[1]).PositiveValue;
                var formattedSignature = new BlobBuilder();
                if (publicKey is ECPublicKeyParameters)
                {
                    var bytes = r.ToByteArray().ToList();
                    while (bytes.Count < 20)
                        bytes.Insert(0, 0);
                    formattedSignature.AddBlob(bytes.ToArray());
                    bytes = s.ToByteArray().ToList();
                    while (bytes.Count < 20)
                        bytes.Insert(0, 0);
                    formattedSignature.AddBlob(bytes.ToArray());
                }
                else
                {
                    var bytes = r.ToByteArrayUnsigned().ToList();
                    while (bytes.Count < 20)
                        bytes.Insert(0, 0);
                    formattedSignature.AddBytes(bytes.ToArray());
                    bytes = s.ToByteArrayUnsigned().ToList();
                    while (bytes.Count < 20)
                        bytes.Insert(0, 0);
                    formattedSignature.AddBytes(bytes.ToArray());
                }
                return formattedSignature.GetBlob();
            }
            else if (publicKey is RsaKeyParameters || publicKey is Ed25519PublicKeyParameters)
            {
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
        public static ISigner GetSigner(
            this ISshKey key,
            SignRequestFlags flags = default(SignRequestFlags)
        )
        {
            var publicKey = key.GetPublicKeyParameters();

            if (publicKey is DsaPublicKeyParameters)
            {
                return SignerUtilities.GetSigner(X9ObjectIdentifiers.IdDsaWithSha1);
            }

            if (publicKey is RsaKeyParameters)
            {
                // flags can influence hash type for RSA keys

                if (flags.HasFlag(SignRequestFlags.SSH_AGENT_RSA_SHA2_512))
                {
                    return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha512WithRsaEncryption);
                }

                if (flags.HasFlag(SignRequestFlags.SSH_AGENT_RSA_SHA2_256))
                {
                    return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
                }

                return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            }

            if (publicKey is ECPublicKeyParameters parameters)
            {
                if (parameters.Q.Curve.Equals(NistNamedCurves.GetByName("P-256")))
                {
                    return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha256);
                }

                if (parameters.Q.Curve.Equals(NistNamedCurves.GetByName("P-384")))
                {
                    return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha384);
                }

                if (parameters.Q.Curve.Equals(NistNamedCurves.GetByName("P-521")))
                {
                    return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha512);
                }

                throw new ArgumentException("unsupported curve", nameof(key));
            }

            if (publicKey is Ed25519PublicKeyParameters)
            {
                return new Ed25519Signer();
            }

            throw new ArgumentException("Unsupported algorithm", nameof(key));
        }
    }
}
