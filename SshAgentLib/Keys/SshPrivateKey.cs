// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2023 David Lechner <david@lechnology.com>

using System;
using System.IO;
using dlech.SshAgentLib;
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
        /// Optional progress callback. Returns normalized progress 0 to 1.
        /// </param>
        /// <param name="comment">
        /// The private key comment.
        /// </param>
        /// <returns>The decrypted parameters.</returns>
        public delegate AsymmetricKeyParameter DecryptFunc(
            GetPassphraseFunc getPassphrase,
            IProgress<double> progress,
            out string comment
        );

        /// <summary>
        /// Called if DecryptFunc found key comment
        /// </summary>
        /// <param name="comment">Found comment</param>
        public delegate void UpdateCommentFunc(string comment);

        private readonly DecryptFunc decrypt;

        /// <summary>
        /// Gets the public key contained in the private key if available, otherwise <c>null</c>.
        /// </summary>
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
            PublicKey = publicKey;
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
        /// <param name="progress">
        /// Optional progress feedback.
        /// </param>
        /// <param name="comment">
        /// The private key comment.
        /// </param>
        /// <returns>The decrypted private key parameters.</returns>
        /// <remarks>
        /// This can be a long running/cpu intensive operation.
        /// </remarks>
        public AsymmetricKeyParameter Decrypt(
            GetPassphraseFunc getPassphrase,
            IProgress<double> progress,
            out string comment
        )
        {
            return decrypt(getPassphrase, progress, out comment);
        }

        /// <summary>
        /// Reads an SSH private key from <paramref name="stream"/>.
        /// </summary>
        /// <param name="stream">The stream containing the key data.</param>
        /// <returns>
        /// An object containing the information read from the file.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="stream"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="FormatException">
        /// Thrown if the key file is not a supported private key format.
        /// </exception>
        public static SshPrivateKey Read(Stream stream)
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

                if (PuttyPrivateKey.FirstLineMatches(firstLine))
                {
                    return PuttyPrivateKey.Read(reader.BaseStream);
                }

                if (PemPrivateKey.FirstLineMatches(firstLine))
                {
                    return PemPrivateKey.Read(reader.BaseStream);
                }

                if (OpensshPrivateKey.FirstLineMatches(firstLine))
                {
                    return OpensshPrivateKey.Read(reader.BaseStream);
                }

                throw new FormatException("unsupported private key format");
            }
        }

        /// <summary>
        /// Creates a new OpenSSH public key file from a private key file.
        /// </summary>
        /// <param name="inStream">Stream for reading the private key file.</param>
        /// <param name="outStream">Stream for writing the public key file.</param>
        /// <param name="getPassphrase">
        /// Callback to get the passphrase for encrypted private keys.
        /// </param>
        /// <param name="comment">Optional comment to include in the public key.</param>
        /// <exception cref="FormatException">
        /// Thrown if the private key file is not supported, is invalid or is a
        /// format that already contains the public key.
        /// </exception>
        public static void CreatePublicKeyFromPrivateKey(
            Stream inStream,
            Stream outStream,
            GetPassphraseFunc getPassphrase,
            string comment = null
        )
        {
            using (var reader = new StreamReader(inStream))
            using (var writer = new StreamWriter(outStream))
            {
                var firstLine = reader.ReadLine();

                // Rewind so next readers start at the beginning.
                reader.BaseStream.Seek(0, SeekOrigin.Begin);

                if (PemPrivateKey.FirstLineMatches(firstLine))
                {
                    var keyPair = PemPrivateKey.ReadKeyPair(reader, getPassphrase);
                    var key = new SshKey(keyPair.Public, keyPair.Private, comment);
                    writer.Write(key.GetAuthorizedKeyString());
                }
                else
                {
                    throw new FormatException(
                        "this private key file key already includes the public key"
                    );
                }
            }
        }
    }
}
