// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// An SSH public key.
    /// </summary>
    public sealed class SshPublicKey
    {
        private readonly OpensshCertificate certificate;

        /// <summary>
        /// Gets the SSH protocol version.
        /// </summary>
        public SshVersion Version { get; }

        /// <summary>
        /// Gets the public key encryption parameters.
        /// </summary>
        public AsymmetricKeyParameter Parameter { get; }

        /// <summary>
        /// Gets the encryption parameter.
        /// </summary>
        private byte[] KeyBlob { get; }

        /// <summary>
        /// Gets the optional comment.
        /// </summary>
        public string Comment { get; }

        /// <summary>
        /// Gets the SHA256 hash of <see cref="KeyBlob"/>.
        /// </summary>
        public string Sha256Hash
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

                builder.Append(GetAlgorithmIdentifier(Parameter, certificate != null));
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

        /// <summary>
        /// Creates a new public key.
        /// </summary>
        /// <param name="version">The SSH version.</param>
        /// <param name="keyBlob">The public key binary data.</param>
        /// <param name="comment">Optional comment.</param>
        public SshPublicKey(SshVersion version, byte[] keyBlob, string comment = null)
        {
            Version = version;
            KeyBlob = keyBlob ?? throw new ArgumentNullException(nameof(keyBlob));
            Comment = comment;

            var parser = new BlobParser(keyBlob);

            switch (version)
            {
                case SshVersion.SSH1:
                    Parameter = parser.ReadSsh1PublicKeyData();
                    break;
                case SshVersion.SSH2:
                    Parameter = parser.ReadSsh2PublicKeyData(out certificate);
                    break;
                default:
                    throw new ArgumentException("unsupported SSH version", nameof(version));
            }
        }

        /// <summary>
        /// Returns a copy of the key with a new comment.
        /// </summary>
        /// <param name="comment">The new comment.</param>
        /// <returns>A new key.</returns>
        public SshPublicKey WithComment(string comment)
        {
            return new SshPublicKey(Version, KeyBlob, comment);
        }

        /// <summary>
        /// Returns a copy of the key with any certificates removed.
        /// </summary>
        public SshPublicKey WithoutCertificate()
        {
            // if there is already no certificate, just return self
            if (certificate == null)
            {
                return this;
            }

            // SSH1 does not support certificates
            Debug.Assert(Version != SshVersion.SSH1);

            // separate the key from the certificate
            var parser = new BlobParser(KeyBlob);
            var parameters = parser.ReadSsh2PublicKeyData(out var _);
            var key = new SshKey(Version, parameters);

            return new SshPublicKey(Version, key.GetPublicKeyBlob(), Comment);
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
            bool hasCertificate
        )
        {
            var algorithm = GetBaseAlgorithmIdentifier(parameters);

            if (hasCertificate)
            {
                algorithm += "-cert-v01@openssh.com";
            }

            return algorithm;
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

            return WithoutCertificate().KeyBlob.SequenceEqual(blob);
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
    }
}
