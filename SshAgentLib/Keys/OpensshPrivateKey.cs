// SPDX-License-Identifier: MIT
// Copyright (c) 2015,2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using SshAgentLib.Crypto;

namespace SshAgentLib.Keys
{
    internal static class OpensshPrivateKey
    {
        private const string pemTypeName = "OPENSSH PRIVATE KEY";

        private const string authMagic = "openssh-key-v1\0";

        private static class CipherName
        {
            public const string None = "none";
            public const string Aes256Cbc = "aes256-cbc";
            public const string Aes256Ctr = "aes256-ctr";

            public static bool IsSupported(string cipherName)
            {
                if (cipherName is null)
                {
                    throw new ArgumentNullException(nameof(cipherName));
                }

                switch (cipherName)
                {
                    case None:
                    case Aes256Cbc:
                    case Aes256Ctr:
                        return true;
                    default:
                        return false;
                }
            }
        }

        private static class KdfName
        {
            public const string None = "none";
            public const string Bcrypt = "bcrypt";

            public static bool IsSupported(string kdfName)
            {
                if (kdfName is null)
                {
                    throw new ArgumentNullException(nameof(kdfName));
                }

                switch (kdfName)
                {
                    case None:
                    case Bcrypt:
                        return true;
                    default:
                        return false;
                }
            }
        }

        private static PemObject ReadPem(Stream stream)
        {
            using (var reader = new StreamReader(stream))
            {
                return new PemReader(reader).ReadPemObject();
            }
        }

        public static SshPrivateKey Read(Stream stream)
        {
            var pem = ReadPem(stream);

            if (pem.Type != pemTypeName)
            {
                throw new SshKeyFileFormatException(
                    $"wrong PEM type, got '{pem.Type}' but expecting '{pemTypeName}'."
                );
            }

            var parser = new BlobParser(pem.Content);

            var magicBytes = parser.ReadBytes(authMagic.Length);

            if (Encoding.UTF8.GetString(magicBytes) != authMagic)
            {
                throw new SshKeyFileFormatException("Bad data - missing AUTH_MAGIC.");
            }

            var cipherName = parser.ReadString();

            if (!CipherName.IsSupported(cipherName))
            {
                throw new SshKeyFileFormatException($"Unsupported cypher name: {cipherName}");
            }

            var kdfName = parser.ReadString();

            if (!KdfName.IsSupported(kdfName))
            {
                throw new SshKeyFileFormatException($"Unsupported KDF name: {kdfName}");
            }

            if (kdfName == KdfName.None && cipherName != CipherName.None)
            {
                throw new SshKeyFileFormatException(
                    "KDF cannot be 'none' when cipher is not 'none'."
                );
            }

            var kdfOptions = parser.ReadBlob();
            var keyCount = parser.ReadUInt32();

            if (keyCount != 1)
            {
                throw new SshKeyFileFormatException("Only one key allowed.");
            }

            var publicKeyBlob = parser.ReadBlob();
            var privateKeyBlob = parser.ReadBlob();

            AsymmetricKeyParameter decrypt(
                SshPrivateKey.GetPassphraseFunc getPassphrase,
                IProgress<double> progress
            )
            {
                var keyAndIV = new byte[32 + 16];

                if (kdfName == KdfName.Bcrypt)
                {
                    var kdfOptionsParser = new BlobParser(kdfOptions);
                    var salt = kdfOptionsParser.ReadBlob();
                    var rounds = kdfOptionsParser.ReadUInt32();

                    var passphrase = getPassphrase();

                    BCrypt.HashUsingOpensshBCryptPbkdf(
                        passphrase,
                        salt,
                        ref keyAndIV,
                        rounds,
                        progress
                    );
                }

                var key = new byte[32];
                Array.Copy(keyAndIV, key, key.Length);
                var iv = new byte[16];
                Array.Copy(keyAndIV, key.Length, iv, 0, iv.Length);

                byte[] decryptedPrivateKeyBlob;

                switch (cipherName)
                {
                    case CipherName.None:
                        decryptedPrivateKeyBlob = privateKeyBlob;
                        break;
                    case CipherName.Aes256Cbc:
                        var aes = Aes.Create();
                        aes.KeySize = 256;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.None;
                        aes.Key = key;
                        aes.IV = iv;

                        if (
                            privateKeyBlob.Length < aes.BlockSize / 8
                            || privateKeyBlob.Length % (aes.BlockSize / 8) != 0
                        )
                        {
                            throw new SshKeyFileFormatException(
                                "Bad private key encrypted length."
                            );
                        }

                        using (var decryptor = aes.CreateDecryptor())
                        {
                            decryptedPrivateKeyBlob = Util.GenericTransform(
                                decryptor,
                                privateKeyBlob
                            );
                        }

                        aes.Clear();
                        break;
                    case CipherName.Aes256Ctr:
                        var ctrCipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
                        ctrCipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                        decryptedPrivateKeyBlob = ctrCipher.DoFinal(privateKeyBlob);
                        break;
                    default:
                        throw new NotSupportedException("unsupported encryption algorithm");
                }

                var privateKeyParser = new BlobParser(decryptedPrivateKeyBlob);

                var checkint1 = privateKeyParser.ReadUInt32();
                var checkint2 = privateKeyParser.ReadUInt32();

                if (checkint1 != checkint2)
                {
                    throw new SshKeyFileFormatException("checkint does not match in private key.");
                }

                var publicKey = privateKeyParser.ReadSsh2PublicKeyData(out var cert);
                var privateKey = privateKeyParser.ReadSsh2KeyData(publicKey);
                var comment = privateKeyParser.ReadString();
                // TODO: what to do with comment and cert?

                return privateKey;
            }

            return new SshPrivateKey(
                new SshPublicKey(SshVersion.SSH2, publicKeyBlob),
                cipherName != CipherName.None,
                kdfName != KdfName.None,
                decrypt
            );
            ;
        }

        internal static bool FirstLineMatches(string firstLine)
        {
            return firstLine == "-----BEGIN OPENSSH PRIVATE KEY-----";
        }
    }
}
