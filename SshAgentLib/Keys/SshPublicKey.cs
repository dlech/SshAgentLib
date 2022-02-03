// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// An SSH public key.
    /// </summary>
    public sealed class SshPublicKey
    {
        /// <summary>
        /// Gets the SSH protocol version.
        /// </summary>
        public SshVersion Version { get; }

        /// <summary>
        /// Gets the public key algorithm.
        /// </summary>
        public PublicKeyAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the encryption parameter.
        /// </summary>
        public byte[] KeyBlob { get; }

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

                builder.Append(Algorithm.GetIdentifier());
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
        /// <param name="algorithm">The SSH key encryption algorithm.</param>
        /// <param name="keyBlob">The public key binary data.</param>
        /// <param name="comment">Optional comment.</param>
        public SshPublicKey(
            SshVersion version,
            PublicKeyAlgorithm algorithm,
            byte[] keyBlob,
            string comment = null
        )
        {
            Version = version;
            Algorithm = algorithm;
            KeyBlob = keyBlob ?? throw new ArgumentNullException(nameof(keyBlob));
            Comment = comment;
        }

        /// <summary>
        /// Returns a copy of the key with a new comment.
        /// </summary>
        /// <param name="comment">The new comment.</param>
        /// <returns>A new key.</returns>
        public SshPublicKey WithComment(string comment)
        {
            return new SshPublicKey(Version, Algorithm, KeyBlob, comment);
        }

        /// <summary>
        /// Returns a copy of the key with any certificates removed.
        /// </summary>
        public SshPublicKey WithoutCertificate()
        {
            // if there is already no certificate, just return self
            if (
                !Algorithm
                    .GetIdentifier()
                    .EndsWith("-cert-v01@openssh.com", StringComparison.Ordinal)
            )
            {
                return this;
            }

            if (Version == SshVersion.SSH1)
            {
                throw new InvalidOperationException("SSH v1 keys do not support certificates.");
            }

            // separate the key from the certificate
            var parser = new BlobParser(KeyBlob);
            var parameters = parser.ReadSsh2PublicKeyData(out var _);
            var key = new SshKey(Version, parameters);

            return new SshPublicKey(Version, key.Algorithm, key.GetPublicKeyBlob(), Comment);
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
            if (stream is null)
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
    }
}
