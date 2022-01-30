//
// OpensshPrivateKeyFormatter.cs
//
// Copyright (c) 2015 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib.Crypto;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Formats openssh public keys.
    /// </summary>
    /// <remarks>
    /// See PROTOCOL.key from the openssh project for more details.
    /// </remarks>
    public class OpensshPrivateKeyFormatter : KeyFormatter
    {
        public const string MARK_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
        public const string MARK_END = "-----END OPENSSH PRIVATE KEY-----";
        const string AUTH_MAGIC = "openssh-key-v1\0";
        const string CIPHERNAME_NONE = "none";
        const string CIPHERNAME_AES256_CBC = "aes256-cbc";
        const string CIPHERNAME_AES256_CTR = "aes256-ctr";
        const string KDFNAME_NONE = "none";
        const string KDFNAME_BCRYPT = "bcrypt";

        public override void Serialize(Stream stream, object obj)
        {
            /* check for required parameters */
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            if (obj == null)
            {
                throw new ArgumentNullException("obj");
            }

            PinnedArray<char> passphrase = null;

            string ciphername;
            if (passphrase == null || passphrase.Data.Length == 0)
            {
                ciphername = KDFNAME_NONE;
            }
            else
            {
                ciphername = KDFNAME_BCRYPT;
            }

            var builder = new BlobBuilder();

            ISshKey sshKey = obj as ISshKey;
            if (sshKey == null)
            {
                throw new ArgumentException("Expected ISshKey", "obj");
            }
            var publicKeyParams = sshKey.GetPublicKeyParameters() as Ed25519PublicKeyParameter;
            var privateKeyParams = sshKey.GetPrivateKeyParameters() as Ed25519PrivateKeyParameter;

            /* writing info headers */
            builder.AddBytes(Encoding.ASCII.GetBytes(AUTH_MAGIC));
            builder.AddStringBlob(ciphername);
            builder.AddStringBlob(ciphername); //kdfname
            builder.AddBlob(new byte[0]); // kdfoptions

            /* writing public key */
            builder.AddInt(1); // number of keys N
            var publicKeyBuilder = new BlobBuilder();
            publicKeyBuilder.AddStringBlob(PublicKeyAlgorithm.ED25519.GetIdentifierString());
            publicKeyBuilder.AddBlob(publicKeyParams.Key);
            builder.AddBlob(publicKeyBuilder.GetBlob());

            /* writing private key */

            BlobBuilder privateKeyBuilder = new BlobBuilder();
            var checkint = new SecureRandom().NextInt();
            privateKeyBuilder.AddInt(checkint);
            privateKeyBuilder.AddInt(checkint);

            privateKeyBuilder.AddStringBlob(PublicKeyAlgorithm.ED25519.GetIdentifierString());
            privateKeyBuilder.AddBlob(publicKeyParams.Key);
            privateKeyBuilder.AddBlob(privateKeyParams.Signature);
            privateKeyBuilder.AddStringBlob(sshKey.Comment);

            if (ciphername == KDFNAME_NONE)
            {
                /* plain-text */
                builder.AddBlob(privateKeyBuilder.GetBlobAsPinnedByteArray().Data);
            }
            else
            {
                byte[] keydata;
                using (MD5 md5 = MD5.Create())
                {
                    keydata = md5.ComputeHash(Encoding.ASCII.GetBytes(passphrase.Data));
                }
                passphrase.Dispose();
            }

            /* writing result to file */
            var builderOutput = builder.GetBlobAsPinnedByteArray();
            using (var writer = new StreamWriter(stream))
            {
                writer.NewLine = "\n";
                writer.WriteLine(MARK_BEGIN);
                var base64Data = Util.ToBase64(builderOutput.Data);
                var base64String = Encoding.UTF8.GetString(base64Data);
                var offset = 0;
                while (offset < base64String.Length)
                {
                    const int maxLineLength = 70;
                    if (offset + maxLineLength > base64String.Length)
                    {
                        writer.WriteLine(base64String.Substring(offset));
                    }
                    else
                    {
                        writer.WriteLine(base64String.Substring(offset, maxLineLength));
                    }
                    offset += maxLineLength;
                }
                writer.WriteLine(MARK_END);
            }
        }

        public override object Deserialize(Stream stream)
        {
            /* check for required parameters */
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            try
            {
                var reader = new StreamReader(stream);
                var firstLine = reader.ReadLine();
                if (firstLine != MARK_BEGIN)
                {
                    throw new KeyFormatterException(
                        "Bad file format - does not have expected header."
                    );
                }
                var base64String = new StringBuilder();
                while (true)
                {
                    var line = reader.ReadLine();
                    if (line == MARK_END)
                    {
                        break;
                    }
                    base64String.Append(line);
                }

                /* reading unencrypted part */
                BlobParser parser = new BlobParser(Util.FromBase64(base64String.ToString()));

                var magicBytes = parser.ReadBytes((uint)AUTH_MAGIC.Length);
                if (Encoding.UTF8.GetString(magicBytes) != AUTH_MAGIC)
                {
                    throw new KeyFormatterException("Bad data - missing AUTH_MAGIC.");
                }

                var ciphername = parser.ReadString();
                if (!IsSupportCipher(ciphername))
                {
                    throw new KeyFormatterException("Unsupported cyphername: " + ciphername);
                }

                var kdfname = parser.ReadString();
                if (kdfname != KDFNAME_BCRYPT && kdfname != KDFNAME_NONE)
                {
                    throw new KeyFormatterException("Unsupported kdfname: " + ciphername);
                }
                if (kdfname == KDFNAME_NONE && ciphername != CIPHERNAME_NONE)
                {
                    throw new KeyFormatterException("Invalid format.");
                }

                var kdfoptions = parser.ReadBlob();
                var keyCount = parser.ReadUInt32();
                if (keyCount != 1)
                {
                    throw new KeyFormatterException("Only one key allowed.");
                }

                var publicKeys = new List<byte[]>();
                for (int i = 0; i < keyCount; i++)
                {
                    publicKeys.Add(parser.ReadBlob());
                }
                var privateKeys = parser.ReadBlob();

                var keyAndIV = new byte[32 + 16];
                if (kdfname == KDFNAME_BCRYPT)
                {
                    var kdfOptionsParser = new BlobParser(kdfoptions);
                    var salt = kdfOptionsParser.ReadBlob();
                    var rounds = kdfOptionsParser.ReadUInt32();

                    var passphrase = GetPassphraseCallbackMethod(null);
                    var passphraseChars = new char[passphrase.Length];
                    var passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(passphrase);
                    for (int i = 0; i < passphrase.Length; i++)
                    {
                        passphraseChars[i] = (char)Marshal.ReadInt16(passphrasePtr, i * 2);
                    }
                    Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
                    BCrypt.HashUsingOpensshBCryptPbkdf(passphraseChars, salt, ref keyAndIV, rounds);
                    Array.Clear(passphraseChars, 0, passphraseChars.Length);
                }

                var key = new byte[32];
                Array.Copy(keyAndIV, key, key.Length);
                var iv = new byte[16];
                Array.Copy(keyAndIV, key.Length, iv, 0, iv.Length);

                switch (ciphername)
                {
                    case CIPHERNAME_AES256_CBC:
                        var aes = Aes.Create();
                        aes.KeySize = 256;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.None;
                        aes.Key = key;
                        aes.IV = iv;

                        if (
                            privateKeys.Length < aes.BlockSize / 8
                            || privateKeys.Length % (aes.BlockSize / 8) != 0
                        )
                        {
                            throw new KeyFormatterException("Bad private key encrypted length.");
                        }

                        using (ICryptoTransform decryptor = aes.CreateDecryptor())
                        {
                            privateKeys = Util.GenericTransform(decryptor, privateKeys);
                        }
                        aes.Clear();
                        break;
                    case CIPHERNAME_AES256_CTR:
                        var ctrCipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
                        ctrCipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                        privateKeys = ctrCipher.DoFinal(privateKeys);
                        break;
                }

                parser = new BlobParser(privateKeys);

                var checkint1 = parser.ReadUInt32();
                var checkint2 = parser.ReadUInt32();
                if (checkint1 != checkint2)
                {
                    throw new KeyFormatterException("checkint does not match in private key.");
                }
                var keys = new List<SshKey>();
                for (int i = 0; i < keyCount; i++)
                {
                    OpensshCertificate cert;
                    var publicKey = parser.ReadSsh2PublicKeyData(out cert);
                    var keyPair = parser.ReadSsh2KeyData(publicKey);
                    var comment = parser.ReadString();
                    var sshKey = new SshKey(SshVersion.SSH2, keyPair, comment, cert);
                    keys.Add(sshKey);
                }
                return keys[0];
            }
            catch (KeyFormatterException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new KeyFormatterException("see inner exception", ex);
            }
        }

        bool IsSupportCipher(string ciphername)
        {
            switch (ciphername)
            {
                case CIPHERNAME_NONE:
                case CIPHERNAME_AES256_CBC:
                case CIPHERNAME_AES256_CTR:
                    return true;
                default:
                    return false;
            }
        }
    }
}
