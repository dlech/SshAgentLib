// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using dlech.SshAgentLib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace SshAgentLib.Keys
{
    internal static class PemPrivateKey
    {
        public static SshPrivateKey Read(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            // make a local copy of the file for easy decryption later
            var contents = new StreamReader(stream).ReadToEnd();

            // read file without decrpting to get metadata
            var reader = new Org.BouncyCastle.Utilities.IO.Pem.PemReader(
                new StringReader(contents)
            );
            var pem = reader.ReadPemObject();

            var isEncrypted = pem.Headers.Cast<PemHeader>().Any(h => h.Name == "DEK-Info");

            SshPrivateKey.DecryptFunc decrypt = (getPassphrase, progress) =>
            {
                var keyPair = ReadKeyPair(new StringReader(contents), getPassphrase);

                // REVISIT: should we validate match with public key?

                return keyPair.Private;
            };

            return new SshPrivateKey(null, isEncrypted, false, decrypt);
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
