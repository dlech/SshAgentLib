// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using static dlech.SshAgentLib.Agent;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// An SSH public key.
    /// </summary>
    public sealed class SshPublicKey
    {
        /// <summary>
        /// Gets the public key encryption parameters.
        /// </summary>
        public AsymmetricKeyParameter Parameter { get; }

        /// <summary>
        /// Gets the encryption parameter.
        /// </summary>
        internal byte[] KeyBlob { get; }

        /// <summary>
        /// Gets the optional comment.
        /// </summary>
        public string Comment { get; }

        /// <summary>
        /// Gets the SHA256 hash of <see cref="KeyBlob"/>.
        /// </summary>
        public string Sha256Fingerprint
        {
            get
            {
                using (var sha = SHA256.Create())
                {
                    var hash = sha.ComputeHash(WithoutCertificate().KeyBlob);
                    return $"SHA256:{Convert.ToBase64String(hash).Trim('=')}";
                }
            }
        }

        /// <summary>
        /// Gets a string suitable for pasting in an <c>authorized_keys</c> file.
        /// </summary>
        public string AuthorizedKeysString
        {
            get
            {
                var builder = new StringBuilder();

                builder.Append(
                    GetAlgorithmIdentifier(Parameter, Certificate != null, Application != null)
                );
                builder.Append(' ');
                builder.Append(Convert.ToBase64String(KeyBlob));

                if (Comment != null)
                {
                    builder.Append(' ');
                    builder.Append(Comment);
                }

                return builder.ToString();
            }
        }

        public byte[] Nonce { get; }

        public OpensshCertificateInfo Certificate { get; }

        /// <summary>
        /// Gets the application for hardware security keys or <c>null</c> if
        /// this key is not associated with a hardware key.
        /// </summary>
        public string Application { get; }

        /// <summary>
        /// Creates a new public key.
        /// </summary>
        /// <param name="version">The SSH version.</param>
        /// <param name="keyBlob">The public key binary data.</param>
        /// <param name="comment">Optional comment (not null).</param>
        public SshPublicKey(byte[] keyBlob, string comment = "")
        {
            KeyBlob = keyBlob ?? throw new ArgumentNullException(nameof(keyBlob));
            Comment = comment ?? throw new ArgumentNullException(nameof(comment));

            var parser = new BlobParser(keyBlob);

            Parameter = parser.ReadSsh2PublicKeyData(
                out var nonce,
                out var certificate,
                out var application
            );
            Nonce = nonce;
            Certificate = certificate;
            Application = application;
        }

        /// <summary>
        /// Returns a copy of the key with a new comment.
        /// </summary>
        /// <param name="comment">The new comment.</param>
        /// <returns>A new key.</returns>
        public SshPublicKey WithComment(string comment)
        {
            return new SshPublicKey(KeyBlob, comment);
        }

        /// <summary>
        /// Returns a copy of the key with any certificates removed.
        /// </summary>
        public SshPublicKey WithoutCertificate()
        {
            // if there is already no certificate, just return self
            if (Certificate == null)
            {
                return this;
            }

            // separate the key from the certificate
            var parser = new BlobParser(KeyBlob);
            var parameters = parser.ReadSsh2PublicKeyData(
                out var nonce,
                out var certificate,
                out var application
            );
            var key = new SshKey(parameters, null, "", null, null, application);

            return new SshPublicKey(key.GetPublicKeyBlob(), Comment);
        }

        /// <summary>
        /// Reads an SSH public key from a stream.
        /// </summary>
        /// <remarks>
        /// The key format is determined by reading the first line of the file.
        /// </remarks>
        /// <param name="stream">The stream containing the key file.</param>
        /// <returns>A new public key object</summary>.
        public static SshPublicKey Read(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using (var reader = new StreamReader(stream))
            {
                var firstLine = reader.ReadLine();

                // Rewind so next readers start at the beginning.
                reader.BaseStream.Seek(0, SeekOrigin.Begin);

                if (firstLine == Rfc4716PublicKey.FirstLine)
                {
                    return Rfc4716PublicKey.Read(reader.BaseStream);
                }

                // OpenSSH format doesn't have a fixed identifier, so use it as default.
                return OpensshPublicKey.Read(reader.BaseStream);
            }
        }

        private static string GetAlgorithmIdentifier(
            AsymmetricKeyParameter parameters,
            bool hasCertificate,
            bool hasApplication
        )
        {
            var algorithm = GetBaseAlgorithmIdentifier(parameters);

            if (hasCertificate)
            {
                algorithm += "-cert-v01@openssh.com";
            }

            if (hasApplication)
            {
                algorithm = "sk-" + algorithm;

                if (!hasCertificate)
                {
                    algorithm += "@openssh.com";
                }
            }

            return algorithm;
        }

        /// <summary>
        /// Tests if this key matches <paramref name="other"/>.
        /// </summary>
        /// <param name="other">Another OpenSSH formatted public key.</param>
        /// <returns>
        /// <c>true</c> if this key matches, otherwise <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool Matches(SshPublicKey other)
        {
            if (other == null)
            {
                throw new ArgumentNullException(nameof(other));
            }

            return KeyBlob.SequenceEqual(other.KeyBlob);
        }

        /// <summary>
        /// Tests if this key matches <paramref name="blob"/>.
        /// </summary>
        /// <param name="blob">An OpenSSH formatted public key blob.</param>
        /// <returns>
        /// <c>true</c> if this key matches, otherwise <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException"></exception>
        public bool Matches(byte[] blob)
        {
            if (blob == null)
            {
                throw new ArgumentNullException(nameof(blob));
            }

            return KeyBlob.SequenceEqual(blob);
        }

        private static string GetBaseAlgorithmIdentifier(AsymmetricKeyParameter parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (parameters is RsaKeyParameters)
            {
                return "ssh-rsa";
            }

            if (parameters is DsaPublicKeyParameters)
            {
                return "ssh-dss";
            }

            if (parameters is ECPublicKeyParameters ecParams)
            {
                if (ecParams.Parameters.Curve.Equals(NistNamedCurves.GetByName("P-256").Curve))
                {
                    return "ecdsa-sha2-nistp256";
                }

                if (ecParams.Parameters.Curve.Equals(NistNamedCurves.GetByName("P-384").Curve))
                {
                    return "ecdsa-sha2-nistp384";
                }

                if (ecParams.Parameters.Curve.Equals(NistNamedCurves.GetByName("P-521").Curve))
                {
                    return "ecdsa-sha2-nistp521";
                }

                throw new ArgumentException("invalid ECDSA curve", nameof(parameters));
            }

            if (parameters is Ed25519PublicKeyParameters)
            {
                return "ssh-ed25519";
            }

            if (parameters is Ed448PublicKeyParameters)
            {
                return "ssh-ed448";
            }

            throw new ArgumentException(
                $"unsupported parameter type: {parameters}",
                nameof(parameters)
            );
        }

        /// <summary>
        /// Verifies a signature of data using this key.
        /// </summary>
        /// <param name="signature">
        /// Encoded data consisting of an algorithm name string and the signature blob.
        /// </param>
        /// <param name="data">
        /// The data that was used to create the signature.
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature is valid, otherwise <c>false</c>.
        /// </returns>
        public bool VerifySignature(byte[] signature, byte[] data)
        {
            var signer = GetSigner(Parameter, out var algorithm);

            var parser = new BlobParser(signature);
            var keyType = parser.ReadString();
            var signatureBlob = parser.ReadBlob();

            if (keyType != algorithm)
            {
                throw new ArgumentException($"wrong key type: {keyType}", nameof(signature));
            }

            signer.Init(false, Parameter);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.VerifySignature(signatureBlob);
        }

        internal static ISigner GetSigner(
            AsymmetricKeyParameter publicKey,
            out string algorithm,
            SignRequestFlags flags = default(SignRequestFlags)
        )
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            if (publicKey is DsaPublicKeyParameters)
            {
                algorithm = "ssh-dss";
                return SignerUtilities.GetSigner(X9ObjectIdentifiers.IdDsaWithSha1);
            }

            if (publicKey is RsaKeyParameters)
            {
                // flags can influence hash type for RSA keys

                if (flags.HasFlag(SignRequestFlags.SSH_AGENT_RSA_SHA2_512))
                {
                    algorithm = "rsa-sha2-512";
                    return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha512WithRsaEncryption);
                }

                if (flags.HasFlag(SignRequestFlags.SSH_AGENT_RSA_SHA2_256))
                {
                    algorithm = "rsa-sha2-256";
                    return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption);
                }

                algorithm = "ssh-rsa";
                return SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            }

            if (publicKey is ECPublicKeyParameters parameters)
            {
                if (parameters.Q.Curve.Equals(NistNamedCurves.GetByName("P-256").Curve))
                {
                    algorithm = "ecdsa-sha2-nistp256";
                    return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha256);
                }

                if (parameters.Q.Curve.Equals(NistNamedCurves.GetByName("P-384").Curve))
                {
                    algorithm = "ecdsa-sha2-nistp384";
                    return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha384);
                }

                if (parameters.Q.Curve.Equals(NistNamedCurves.GetByName("P-521").Curve))
                {
                    algorithm = "ecdsa-sha2-nistp521";
                    return SignerUtilities.GetSigner(X9ObjectIdentifiers.ECDsaWithSha512);
                }

                throw new ArgumentException("unsupported curve", nameof(publicKey));
            }

            if (publicKey is Ed25519PublicKeyParameters)
            {
                algorithm = "ssh-ed25519";
                return new Ed25519Signer();
            }

            throw new ArgumentException("Unsupported algorithm", nameof(publicKey));
        }
    }
}
