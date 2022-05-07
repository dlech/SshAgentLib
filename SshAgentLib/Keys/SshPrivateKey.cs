// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Security;
using Org.BouncyCastle.Crypto;

namespace SshAgentLib.Keys
{
    public sealed class SshPrivateKey
    {
        public delegate SecureString GetPassphraseFunc(string comment);

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

        readonly object privateKeyLock = new object();
        AsymmetricKeyParameter privateKey;
        private readonly DecryptFunc decrypt;

        public SshPublicKey PublicKey { get; }

        public AsymmetricKeyParameter PrivateKey
        {
            get
            {
                lock (privateKeyLock)
                {
                    if (privateKey == null)
                    {
                        throw new InvalidOperationException(
                            "key must be decrypted before using private key"
                        );
                    }

                    return privateKey;
                }
            }
        }

        public SshPrivateKey(SshPublicKey publicKey, DecryptFunc decrypt)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            this.decrypt = decrypt ?? throw new ArgumentNullException(nameof(decrypt));
        }

        public void Decrypt(GetPassphraseFunc getPassphrase, IProgress<double> progress = null)
        {
            lock (privateKeyLock)
            {
                if (privateKey != null)
                {
                    // already decrypted
                    return;
                }

                privateKey = decrypt(getPassphrase, progress);
            }
        }

        public void Encrypt()
        {
            lock (privateKeyLock)
            {
                privateKey = null;
            }
        }

        public static SshPrivateKey Read(Stream stream)
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

                if (OpensshPrivateKey.FirstLineMatches(firstLine))
                {
                    return OpensshPrivateKey.Read(reader.BaseStream);
                }

                throw new SshKeyFileFormatException("unsupported private key format");
            }
        }
    }
}
