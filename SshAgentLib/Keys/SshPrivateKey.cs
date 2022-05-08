// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using Org.BouncyCastle.Crypto;

namespace SshAgentLib.Keys
{
    public sealed class SshPrivateKey
    {
        public delegate byte[] GetPassphraseFunc();

        /// <summary>
        /// Decryption callback delegate.
        /// </summary>
        /// <param name="getPassphrase">
        /// A callback to get the passphrase. Can be <c>null</c> if the private key is not encrypted.
        /// </param>
        /// <param name="progress">
        /// Optional progress callback. Returns normalized progres 0 to 1.
        /// </param>
        /// <returns>The decrypted parameters.</returns>
        public delegate AsymmetricKeyParameter DecryptFunc(
            GetPassphraseFunc getPassphrase,
            IProgress<double> progress
        );

        private readonly DecryptFunc decrypt;

        public SshPublicKey PublicKey { get; }

        /// <summary>
        /// Returns <c>true</c> is the key is encrypted with a passphrase, otherwise <c>false</c>.
        /// </summary>
        public bool IsEncrypted { get; }

        /// <summary>
        /// Returns <c>true</c> if the key has a key derivation function, otherwise <c>false</c>.
        /// </summary>
        public bool HasKdf { get; }

        public SshPrivateKey(
            SshPublicKey publicKey,
            bool isEncrypted,
            bool hasKdf,
            DecryptFunc decrypt
        )
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            IsEncrypted = isEncrypted;
            HasKdf = hasKdf;
            this.decrypt = decrypt ?? throw new ArgumentNullException(nameof(decrypt));
        }

        /// <summary>
        /// Decrypts the private key.
        /// </summary>
        /// <param name="getPassphrase">
        /// Callback to get the passphrase. Can be <c>null</c> for unencrypted keys.
        /// </param>
        /// <param name="progress">Optional progress feedback.</param>
        /// <returns>The decrypted private key parameters.</returns>
        /// <remarks>
        /// This can be a long running/cpu intensive operation.
        /// </remarks>
        public AsymmetricKeyParameter Decrypt(
            GetPassphraseFunc getPassphrase,
            IProgress<double> progress = null
        )
        {
            return decrypt(getPassphrase, progress);
        }

        /// <summary>
        /// Reads an SSH private key from <paramref name="stream"/>.
        /// </summary>
        /// <param name="stream">The stream containing the key data.</param>
        /// <param name="publicKey">
        /// A public key that matches the private key. This is required for legacy
        /// private key file formats that do not contain public key information and
        /// ignored for private key file formats that already include the public key.
        /// </param>
        /// <returns>
        /// An object containing the information read from the file.
        /// </returns>
        /// <exception cref="PublicKeyRequiredException">
        /// Throw if <paramref name="publicKey"/> is required for the provided key.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="stream"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="FormatException">
        /// Thrown if the key file is not a supported private key format.
        /// </exception>
        public static SshPrivateKey Read(Stream stream, SshPublicKey publicKey = null)
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

                if (PuttyPrivateKey.FirstLineMatches(firstLine))
                {
                    return PuttyPrivateKey.Read(reader.BaseStream);
                }

                if (PemPrivateKey.FirstLineMatches(firstLine))
                {
                    if (publicKey == null) {
                        throw new PublicKeyRequiredException();
                    }

                    return PemPrivateKey.Read(reader.BaseStream, publicKey);
                }

                if (OpensshPrivateKey.FirstLineMatches(firstLine))
                {
                    return OpensshPrivateKey.Read(reader.BaseStream);
                }

                throw new FormatException("unsupported private key format");
            }
        }

        /// <summary>
        /// Indicates that a public key is required for the key type given.
        /// </summary>
        public sealed class PublicKeyRequiredException : ArgumentException {
            public PublicKeyRequiredException() : base("public key is required for this key type", "publicKey") {}
        }
    }
}
