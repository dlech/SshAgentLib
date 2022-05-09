// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace SshAgentLib.Keys
{
    internal static class PemPrivateKey
    {
        public static SshPrivateKey Read(Stream stream, SshPublicKey publicKey)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            // make a local copy of the file for easy decryption later
            var contents = new StreamReader(stream).ReadToEnd();

            // read file without decrpting to get metadata
            var reader = new Org.BouncyCastle.Utilities.IO.Pem.PemReader(
                new StringReader(contents)
            );
            var pem = reader.ReadPemObject();

            var isEncrypted = pem.Headers.Cast<PemHeader>().Any(h => h.Name == "DEK-Info");

            switch (pem.Type)
            {
                case "RSA PRIVATE KEY":
                    if (!(publicKey.Parameter is RsaKeyParameters))
                    {
                        throw new ArgumentException("private key is RSA but public key is not");
                    }
                    break;
                case "DSA PRIVATE KEY":
                    if (!(publicKey.Parameter is DsaPublicKeyParameters))
                    {
                        throw new ArgumentException("private key is DSA but public key is not");
                    }
                    break;
                case "EC PRIVATE KEY":
                    if (!(publicKey.Parameter is ECPublicKeyParameters))
                    {
                        throw new ArgumentException("private key is EC but public key is not");
                    }
                    break;
                default:
                    throw new NotSupportedException($"unsupported key type: '{pem.Type}'");
            }

            SshPrivateKey.DecryptFunc decrypt = (getPassphrase, progress) =>
            {
                var keyPair = ReadKeyPair(new StringReader(contents), getPassphrase);

                // REVISIT: should we validate match with public key?

                return keyPair.Private;
            };

            return new SshPrivateKey(publicKey, isEncrypted, false, decrypt);
        }

        internal static AsymmetricCipherKeyPair ReadKeyPair(
            TextReader reader,
            SshPrivateKey.GetPassphraseFunc getPassphrase
        )
        {
            var privReader = new Org.BouncyCastle.OpenSsl.PemReader(
                reader,
                new PasswordFinder(getPassphrase)
            );

            var keyPair = privReader.ReadObject();

            return (AsymmetricCipherKeyPair)keyPair;
        }

        public static bool FirstLineMatches(string firstLine)
        {
            if (firstLine == null)
            {
                throw new ArgumentNullException(nameof(firstLine));
            }

            return Regex.IsMatch(firstLine, "-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----");
        }

        private class PasswordFinder : IPasswordFinder
        {
            private readonly SshPrivateKey.GetPassphraseFunc getPassphrase;

            public PasswordFinder(SshPrivateKey.GetPassphraseFunc getPassphrase)
            {
                this.getPassphrase = getPassphrase;
            }

            public char[] GetPassword()
            {
                if (getPassphrase == null)
                {
                    return null;
                }

                return Encoding.UTF8.GetString(getPassphrase()).ToCharArray();
            }
        }
    }
}
