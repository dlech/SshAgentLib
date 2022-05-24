// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2013,2015,2017,2022 David Lechner <david@lechnology.com>

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib;
using SshAgentLib.Crypto;
using Org.BouncyCastle.Crypto;

namespace SshAgentLib.Keys
{
    internal static class PuttyPrivateKey
    {
        private static class HeaderKey
        {
            /// <summary>
            /// Key that identifies the file version and the public key algorithm
            /// It is the first thing in the file, so it can also be used as a signature
            /// for a quick and dirty file format test.
            /// </summary>
            public const string PuttyUserKeyFile = "PuTTY-User-Key-File-";

            /// <summary>
            /// Key that indicates the line containing the private key encryption algorithm
            /// </summary>
            public const string Encryption = "Encryption";

            /// <summary>
            /// Key that indicates the line containing the user comment
            /// </summary>
            public const string Comment = "Comment";

            /// <summary>
            /// Key that indicates that the public key follows on the next line
            /// and the length of the key in lines
            /// </summary>
            public const string PublicLines = "Public-Lines";

            public const string KeyDerivation = "Key-Derivation";

            public const string Argon2Memory = "Argon2-Memory";

            public const string Argon2Passes = "Argon2-Passes";

            public const string Argon2Parallelism = "Argon2-Parallelism";

            public const string Argon2Salt = "Argon2-Salt";

            /// <summary>
            /// Key that indicates that the private key follows on the next line
            /// and the length of the key in lines
            /// </summary>
            public const string PrivateLines = "Private-Lines";

            /// <summary>
            /// Key that indicates that the line contains the hash of the private key
            /// (version >= 2 file format only)
            /// </summary>
            public const string PrivateMAC = "Private-MAC";

            /// <summary>
            /// Key that indicates that the line contains the hash of the private key
            /// (version 1 file format only)
            /// </summary>
            public const string PrivateHash = "Private-Hash";
        }

        private static class Encryption
        {
            public const string None = "none";
            public const string Aes256Cbc = "aes256-cbc";
        }

        private static class Salt
        {
            public const string Decrypt1 = "\0\0\0\0";
            public const string Decrypt2 = "\0\0\0\x1";
            public const string MAC = "putty-private-key-file-mac-key";
        }

        private static readonly char[] headerDelimeter = { ':' };

        public static SshPrivateKey Read(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var reader = new StreamReader(stream, Encoding.GetEncoding(1252));

            reader.ReadVersionHeader(out var version, out var algorithm);

            if (version != "1" && version != "2" && version != "3")
            {
                throw new FormatException("unsupported version");
            }

            // REVISIT: consider emitting warning for v1 format

            var encryption = reader.ReadHeader(HeaderKey.Encryption);
            var comment = reader.ReadHeader(HeaderKey.Comment);
            var publicKeyLines = int.Parse(reader.ReadHeader(HeaderKey.PublicLines));

            var publicKeyString = new StringBuilder(publicKeyLines * 64);

            for (int i = 0; i < publicKeyLines; i++)
            {
                publicKeyString.Append(reader.ReadLine());
            }

            var publicKeyBlob = Convert.FromBase64String(publicKeyString.ToString());

            var publicKey = new SshPublicKey(publicKeyBlob, comment);

            var argon2Parameter = new Argon2.Parameters();

            if (version == "3" && encryption != Encryption.None)
            {
                var keyDerivation = reader.ReadHeader(HeaderKey.KeyDerivation);

                if (
                    keyDerivation != Argon2.KeyDerivation.Argon2id
                    && keyDerivation != Argon2.KeyDerivation.Argon2d
                    && keyDerivation != Argon2.KeyDerivation.Argon2i
                )
                {
                    throw new NotSupportedException("unsupported key derivation");
                }

                argon2Parameter.Algorithm = keyDerivation;
                argon2Parameter.Memory = int.Parse(reader.ReadHeader(HeaderKey.Argon2Memory));
                argon2Parameter.Passes = int.Parse(reader.ReadHeader(HeaderKey.Argon2Passes));
                argon2Parameter.Parallelism = int.Parse(
                    reader.ReadHeader(HeaderKey.Argon2Parallelism)
                );
                argon2Parameter.Salt = Util.FromHex(reader.ReadHeader(HeaderKey.Argon2Salt));
            }

            var privateKeyLines = int.Parse(reader.ReadHeader(HeaderKey.PrivateLines));

            var privateKeyString = new StringBuilder(privateKeyLines * 64);

            for (int i = 0; i < privateKeyLines; i++)
            {
                privateKeyString.Append(reader.ReadLine());
            }

            var privateKeyBlob = Convert.FromBase64String(privateKeyString.ToString());

            var privateMac = Util.FromHex(
                reader.ReadHeader(version == "1" ? HeaderKey.PrivateHash : HeaderKey.PrivateMAC)
            );

            SshPrivateKey.DecryptFunc decrypt = (getPassphrase, progress) =>
            {
                byte[] decryptedPrivateKeyBlob;
                byte[] macKey;

                switch (encryption)
                {
                    case Encryption.None:
                        decryptedPrivateKeyBlob = privateKeyBlob;

                        if (version == "2")
                        {
                            using (var sha = SHA1.Create())
                            {
                                macKey = sha.ComputeHash(Encoding.UTF8.GetBytes(Salt.MAC));
                            }
                        }
                        else
                        {
                            macKey = Array.Empty<byte>();
                        }
                        break;
                    case Encryption.Aes256Cbc:
                        byte[] cipherKey;
                        byte[] vi;

                        var passphrase = getPassphrase();

                        switch (version)
                        {
                            case "1":
                            case "2":
                                GetCipherParameters(passphrase, out cipherKey, out vi, out macKey);
                                break;
                            case "3":
                                // REVISIT: this is potentially long running and should report progress
                                GetCipherParametersV3(
                                    passphrase,
                                    argon2Parameter,
                                    out cipherKey,
                                    out vi,
                                    out macKey
                                );
                                break;
                            default:
                                throw new InvalidOperationException(
                                    "bad version - this should be unreachable"
                                );
                        }

                        decryptedPrivateKeyBlob = DecryptAes256Cbc(cipherKey, vi, privateKeyBlob);

                        break;
                    default:
                        throw new InvalidOperationException(
                            "bad encryption - this should be unreachable"
                        );
                }

                byte[] hashData;

                if (version == "1")
                {
                    hashData = decryptedPrivateKeyBlob;
                }
                else
                {
                    var builder = new BlobBuilder();
                    builder.AddStringBlob(algorithm);
                    builder.AddStringBlob(encryption);
                    builder.AddBlob(Encoding.GetEncoding(1252).GetBytes(comment));
                    builder.AddBlob(publicKeyBlob);
                    builder.AddBlob(decryptedPrivateKeyBlob);

                    hashData = builder.GetBlob();
                }

                var computedHash = ComputeHash(version, hashData, macKey);

                if (!privateMac.SequenceEqual(computedHash))
                {
                    // private key data should start with 3 bytes with value 0 if it was
                    // properly decrypted or does not require decryption
                    if (
                        (privateKeyBlob[0] == 0)
                        && (privateKeyBlob[1] == 0)
                        && (privateKeyBlob[2] == 0)
                    )
                    {
                        // so if they bytes are there, passphrase decrypted properly and
                        // something else is wrong with the file contents
                        throw new FormatException("corrupt file");
                    }

                    // if the bytes are not zeros, we assume that the data was not
                    // properly decrypted because the passphrase was incorrect.
                    throw new FormatException("wrong passphrase");
                }

                var parser = new BlobParser(decryptedPrivateKeyBlob);
                return parser.ReadPuttyPrivateKeyData(publicKey.Parameter);
            };

            return new SshPrivateKey(
                publicKey,
                encryption != Encryption.None,
                argon2Parameter.Algorithm != null,
                decrypt
            );
        }

        internal static bool FirstLineMatches(string firstLine)
        {
            if (firstLine == null)
            {
                throw new ArgumentNullException(nameof(firstLine));
            }

            return firstLine.StartsWith(HeaderKey.PuttyUserKeyFile, StringComparison.Ordinal);
        }

        private static void ReadVersionHeader(
            this StreamReader reader,
            out string version,
            out string algorithm
        )
        {
            var items = reader.ReadLine().Split(headerDelimeter, 2);

            if (items.Length != 2)
            {
                throw new FormatException("invalid header line");
            }

            var key = items[0].Trim();

            if (!key.StartsWith(HeaderKey.PuttyUserKeyFile, StringComparison.Ordinal))
            {
                throw new FormatException($"File does not start with {HeaderKey.PuttyUserKeyFile}");
            }

            version = key.Remove(0, HeaderKey.PuttyUserKeyFile.Length);
            algorithm = items[1].Trim();
        }

        private static string ReadHeader(this StreamReader reader, string expectedKey)
        {
            var items = reader.ReadLine().Split(headerDelimeter, 2);

            if (items.Length != 2)
            {
                throw new FormatException("invalid header line");
            }

            var key = items[0].Trim();

            if (key != expectedKey)
            {
                throw new FormatException($"expecting header '{expectedKey}:` but got '{key}:'");
            }

            return items[1].Trim();
        }

        private static void GetCipherParameters(
            byte[] passphrase,
            out byte[] cipherKey,
            out byte[] iv,
            out byte[] macKey
        )
        {
            using (var sha = SHA1.Create())
            {
                sha.Initialize();
                var key = new List<byte>();
                iv = new byte[16];

                var hashData = new byte[Salt.Decrypt1.Length + passphrase.Length];

                Array.Copy(Encoding.UTF8.GetBytes(Salt.Decrypt1), hashData, Salt.Decrypt1.Length);

                Array.Copy(passphrase, 0, hashData, Salt.Decrypt1.Length, passphrase.Length);

                sha.ComputeHash(hashData);
                key.AddRange(sha.Hash);

                Array.Copy(Encoding.UTF8.GetBytes(Salt.Decrypt2), hashData, Salt.Decrypt2.Length);

                sha.ComputeHash(hashData);
                key.AddRange(sha.Hash);

                var keySize = 256 / 8; // convert bits to bytes
                key.RemoveRange(keySize, key.Count - keySize); // remove extra bytes
                cipherKey = key.ToArray();

                hashData = new byte[Salt.MAC.Length + passphrase.Length];

                Array.Copy(Encoding.UTF8.GetBytes(Salt.MAC), hashData, Salt.MAC.Length);
                Array.Copy(passphrase, 0, hashData, Salt.MAC.Length, passphrase.Length);

                macKey = sha.ComputeHash(hashData);
            }
        }

        private static void GetCipherParametersV3(
            byte[] passphrase,
            Argon2.Parameters parameters,
            out byte[] cipherKey,
            out byte[] iv,
            out byte[] macKey
        )
        {
            using (var hasher = Argon2.CreateHasher(parameters, passphrase))
            {
                const int cipherLength = 32;
                const int ivLength = 16;
                const int macLength = 32;

                var kdf = hasher.GetBytes(cipherLength + ivLength + macLength);

                cipherKey = kdf.Skip(0).Take(cipherLength).ToArray();
                iv = kdf.Skip(cipherLength).Take(ivLength).ToArray();
                macKey = kdf.Skip(cipherLength + ivLength).Take(macLength).ToArray();
            }
        }

        private static byte[] DecryptAes256Cbc(
            byte[] cipherKey,
            byte[] iv,
            byte[] encryptedPrivateKeyBlob
        )
        {
            /* decrypt private key */

            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = cipherKey;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return Util.GenericTransform(decryptor, encryptedPrivateKeyBlob);
                }
            }
        }

        private static byte[] ComputeHash(string version, byte[] data, byte[] macKey)
        {
            switch (version)
            {
                case "1":
                    using (var sha = SHA1.Create())
                    {
                        return sha.ComputeHash(data);
                    }
                case "2":
                    using (var hmac = HMAC.Create())
                    {
                        hmac.Key = macKey;
                        return hmac.ComputeHash(data);
                    }
                case "3":
                    using (var hmac = new HMACSHA256(macKey))
                    {
                        return hmac.ComputeHash(data);
                    }
                default:
                    throw new NotSupportedException("unsupported file format version");
            }
        }
    }
}
