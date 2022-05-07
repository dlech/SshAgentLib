//
// Ppkformatter.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013,2015,2017,2022 David Lechner
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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SshAgentLib;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Used to read PuTTY Private Key (.ppk) files
    /// </summary>
    public class PpkFormatter : KeyFormatter
    {
        #region -- Constants --

        private const string cPrivateKeyDecryptSalt1 = "\0\0\0\0";
        private const string cPrivateKeyDecryptSalt2 = "\0\0\0\x1";
        private const string cMACKeySalt = "putty-private-key-file-mac-key";
        internal const string ALGORITHM_NONE = "none";
        internal const string ALGORITHM_AES256_CBC = "aes256-cbc";

        /// <summary>
        /// Key that identifies the file version and the public key algorithm
        /// It is the first thing in the file, so it can also be used as a signature
        /// for a quick and dirty file format test.
        /// </summary>
        private const string puttyUserKeyFileKey = "PuTTY-User-Key-File-";

        /// <summary>
        /// Key that indicates the line containing the private key encryption algorithm
        /// </summary>
        private const string privateKeyEncryptionKey = "Encryption";

        /// <summary>
        /// Key that indicates the line containing the user comment
        /// </summary>
        private const string commentKey = "Comment";

        /// <summary>
        /// Key that indicates that the public key follows on the next line
        /// and the length of the key in lines
        /// </summary>
        private const string publicKeyLinesKey = "Public-Lines";

        private const string keyDerivationKey = "Key-Derivation";

        private const string argonMemoryKey = "Argon2-Memory";

        private const string argonPassesKey = "Argon2-Passes";

        private const string argonParallelismKey = "Argon2-Parallelism";

        private const string argonSaltKey = "Argon2-Salt";

        /// <summary>
        /// Key that indicates that the private key follows on the next line
        /// and the length of the key in lines
        /// </summary>
        private const string privateKeyLinesKey = "Private-Lines";

        /// <summary>
        /// Key that indicates that the line contains the hash of the private key
        /// (version 2 file format only)
        /// </summary>
        private const string privateMACKey = "Private-MAC";

        /// <summary>
        /// Key that indicates that the line contains the hash of the private key
        /// (version 1 file format only)
        /// </summary>
        private const string privateHashKey = "Private-Hash";

        /// <summary>
        /// The delimiter used by the file
        /// </summary>
        private const char cDelimeter = ':';

        #endregion -- Constants --


        #region -- Enums --

        /// <summary>
        /// contains fields with valid file version strings
        /// </summary>
        internal enum Version
        {
            V1,
            V2,
            V3,
        }

        /// <summary>
        /// Valid private key encryption algorithms
        /// </summary>
        internal enum PrivateKeyAlgorithm
        {
            None,
            AES256_CBC
        }

        #endregion -- Enums --


        #region -- structures --

        private struct FileData
        {
            /// <summary>
            /// File format version (one of FileVersions members)
            /// Callers of this method should warn user
            /// that version 1 has security issue and should not be used
            /// </summary>
            public Version ppkFileVersion;

            /// <summary>
            /// Public key algorithm
            /// One of <see cref="PublicKeyAlgorithms"/>
            /// </summary>
            public PublicKeyAlgorithm publicKeyAlgorithm;

            /// <summary>
            /// Private key encryption algorithm
            /// One of <see cref="PrivateKeyAlgorithm"/>
            /// </summary>
            public PrivateKeyAlgorithm privateKeyAlgorithm;

            /// <summary>
            /// The public key
            /// </summary>
            public byte[] publicKeyBlob;

            /// <summary>
            /// public key comment
            /// </summary>
            public string comment;

            public KeyDerivation kdfAlgorithm;
            public Dictionary<string, object> kdfParameters;

            /// <summary>
            /// The private key.
            /// </summary>
            public byte[] privateKeyBlob;

            /// <summary>
            /// The private key hash.
            /// </summary>
            public byte[] privateMAC;

            /// <summary>
            /// <see cref="privateMACString"/> is a HMAC as opposed to the old format
            /// </summary>
            public bool isHMAC;
            public SecureString passphrase;
        }

        #endregion -- structures --


        #region -- Delegates --

        /// <summary>
        /// Implementation of this function should warn the user that they are using
        /// an old file format that has know security issues.
        /// </summary>
        public delegate void WarnOldFileFormatCallback();

        #endregion -- Delegates --


        #region -- Properties --

        public WarnOldFileFormatCallback WarnOldFileFormatCallbackMethod { get; set; }

        #endregion  -- Properties --


        #region -- Constructors --



        #endregion -- Constructors --


        #region -- Public Methods --

        public override void Serialize(Stream aStream, object aObject)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Parses the data from a PuTTY Private Key (.ppk) file.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <exception cref="dlech.SshAgentLib.PpkFormatterException">
        /// there was a problem parsing the file data
        /// </exception>
        /// <exception cref="CallBackNullException">
        /// data is encrypted and passphrase callback is null
        /// </exception>
        public override ISshKey Deserialize(Stream stream, IProgress<double> progress = null)
        {
            var fileData = new FileData();

            /* check for required parameters */
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            string line;
            var pair = new string[2];
            int lineCount,
                i;

            var reader = new StreamReader(stream, Encoding.GetEncoding(1252));
            char[] delimArray = { cDelimeter };

            try
            {
                /* read file version */
                line = reader.ReadLine();
                pair = line.Split(delimArray, 2);
                if (!pair[0].StartsWith(puttyUserKeyFileKey))
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        puttyUserKeyFileKey + " expected"
                    );
                }
                var ppkFileVersion = pair[0].Remove(0, puttyUserKeyFileKey.Length);
                if (!ppkFileVersion.TryParseVersion(ref fileData.ppkFileVersion))
                {
                    throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileVersion);
                }
                if (fileData.ppkFileVersion == Version.V1)
                {
                    if (WarnOldFileFormatCallbackMethod != null)
                    {
                        WarnOldFileFormatCallbackMethod.Invoke();
                    }
                }

                /* read public key encryption algorithm type */
                var algorithm = pair[1].Trim();

                try
                {
                    fileData.publicKeyAlgorithm = KeyFormatIdentifier.Parse(algorithm);
                }
                catch (ArgumentException)
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.PublicKeyEncryption
                    );
                }

                /* read private key encryption algorithm type */
                line = reader.ReadLine();
                pair = line.Split(delimArray, 2);
                if (pair[0] != privateKeyEncryptionKey)
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        privateKeyEncryptionKey + " expected"
                    );
                }
                algorithm = pair[1].Trim();
                if (!algorithm.TryParsePrivateKeyAlgorithm(ref fileData.privateKeyAlgorithm))
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.PrivateKeyEncryption
                    );
                }

                /* read comment */
                line = reader.ReadLine();
                pair = line.Split(delimArray, 2);
                if (pair[0] != commentKey)
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        commentKey + " expected"
                    );
                }
                fileData.comment = pair[1].Trim();

                /* read public key */
                line = reader.ReadLine();
                pair = line.Split(delimArray, 2);
                if (pair[0] != publicKeyLinesKey)
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        publicKeyLinesKey + " expected"
                    );
                }
                if (!int.TryParse(pair[1], out lineCount))
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        "integer expected"
                    );
                }
                var publicKeyString = string.Empty;
                for (i = 0; i < lineCount; i++)
                {
                    publicKeyString += reader.ReadLine();
                }
                fileData.publicKeyBlob = Convert.FromBase64String(publicKeyString);

                /* read kdf parameters */
                if (
                    fileData.privateKeyAlgorithm != PrivateKeyAlgorithm.None
                    && fileData.ppkFileVersion == Version.V3
                )
                {
                    fileData.kdfParameters = new Dictionary<string, object>();

                    line = reader.ReadLine();
                    pair = line.Split(delimArray, 2);
                    if (pair[0] != keyDerivationKey)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            $"{keyDerivationKey} expected"
                        );
                    }

                    algorithm = pair[1].Trim();
                    try
                    {
                        fileData.kdfAlgorithm = (KeyDerivation)Enum.Parse(
                            typeof(KeyDerivation),
                            algorithm
                        );
                    }
                    catch (Exception e) when (e is ArgumentException || e is OverflowException)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            "unsupported key derivation algorithm"
                        );
                    }

                    if (!algorithm.StartsWith("Argon2"))
                    {
                        throw new NotImplementedException();
                    }

                    line = reader.ReadLine();
                    pair = line.Split(delimArray, 2);
                    if (pair[0] != argonMemoryKey)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            argonMemoryKey + "expected"
                        );
                    }

                    try
                    {
                        fileData.kdfParameters[argonMemoryKey] = int.Parse(pair[1].Trim());
                    }
                    catch (Exception e)
                        when (e is ArgumentNullException
                            || e is FormatException
                            || e is OverflowException
                        )
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            "expected an int"
                        );
                    }

                    line = reader.ReadLine();
                    pair = line.Split(delimArray, 2);
                    if (pair[0] != argonPassesKey)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            argonPassesKey + "expected"
                        );
                    }

                    try
                    {
                        fileData.kdfParameters[argonPassesKey] = int.Parse(pair[1].Trim());
                    }
                    catch (Exception e)
                        when (e is ArgumentNullException
                            || e is FormatException
                            || e is OverflowException
                        )
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            "expected an int"
                        );
                    }

                    line = reader.ReadLine();
                    pair = line.Split(delimArray, 2);
                    if (pair[0] != argonParallelismKey)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            argonParallelismKey + "expected"
                        );
                    }

                    try
                    {
                        fileData.kdfParameters[argonParallelismKey] = int.Parse(pair[1].Trim());
                    }
                    catch (Exception e)
                        when (e is ArgumentNullException
                            || e is FormatException
                            || e is OverflowException
                        )
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            "expected an int"
                        );
                    }

                    line = reader.ReadLine();
                    pair = line.Split(delimArray, 2);
                    if (pair[0] != argonSaltKey)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            argonSaltKey + "expected"
                        );
                    }

                    try
                    {
                        fileData.kdfParameters[argonSaltKey] = Util.FromHex(pair[1].Trim());
                    }
                    catch (ArgumentException)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            "expected a hex string"
                        );
                    }
                }

                /* read private key */
                line = reader.ReadLine();
                pair = line.Split(delimArray, 2);
                if (pair[0] != privateKeyLinesKey)
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        privateKeyLinesKey + " expected"
                    );
                }
                if (!int.TryParse(pair[1], out lineCount))
                {
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.FileFormat,
                        "integer expected"
                    );
                }
                var privateKeyString = string.Empty;
                for (i = 0; i < lineCount; i++)
                {
                    privateKeyString += reader.ReadLine();
                }
                fileData.privateKeyBlob = Convert.FromBase64String(privateKeyString);

                /* read MAC */
                line = reader.ReadLine();
                pair = line.Split(delimArray, 2);
                if (pair[0] != privateMACKey)
                {
                    fileData.isHMAC = false;
                    if (pair[0] != privateHashKey || fileData.ppkFileVersion != Version.V1)
                    {
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileFormat,
                            privateMACKey + " expected"
                        );
                    }
                }
                else
                {
                    fileData.isHMAC = true;
                }
                var privateMACString = pair[1].Trim();
                fileData.privateMAC = Util.FromHex(privateMACString);

                /* get passphrase and decrypt private key if required */
                if (fileData.privateKeyAlgorithm != PrivateKeyAlgorithm.None)
                {
                    if (GetPassphraseCallbackMethod == null)
                    {
                        throw new CallbackNullException();
                    }
                    fileData.passphrase = GetPassphraseCallbackMethod.Invoke(fileData.comment);
                    DecryptPrivateKey(ref fileData);
                }

                VerifyIntegrity(fileData);

                var cipherKeyPair = CreateCipherKeyPair(
                    fileData.publicKeyAlgorithm,
                    fileData.publicKeyBlob,
                    fileData.privateKeyBlob
                );
                var key = new SshKey(SshVersion.SSH2, cipherKeyPair, fileData.comment);
                return key;
            }
            catch (PpkFormatterException)
            {
                throw;
            }
            catch (CallbackNullException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PpkFormatterException(
                    PpkFormatterException.PpkErrorType.FileFormat,
                    "See inner exception.",
                    ex
                );
            }
            finally
            {
                if (fileData.publicKeyBlob != null)
                {
                    Array.Clear(fileData.publicKeyBlob, 0, fileData.publicKeyBlob.Length);
                }

                if (fileData.privateMAC != null)
                {
                    Array.Clear(fileData.privateMAC, 0, fileData.privateMAC.Length);
                }
                reader.Close();
            }
        }

        #endregion -- Public Methods --


        #region -- Private Methods --

        private static void argonKeys(
            FileData fileData,
            out byte[] cipherKey,
            out byte[] iv,
            out byte[] macKey
        )
        {
            var cipherLength = 32;
            var ivLength = 16;
            var macLength = 32;

            if (fileData.privateKeyAlgorithm == PrivateKeyAlgorithm.None)
            {
                cipherKey = null;
                iv = null;
                macKey = new byte[0];
                return;
            }

            var passphrase = fileData.passphrase.ToAnsiArray();

            Argon2 hasher;
            switch (fileData.kdfAlgorithm)
            {
                case KeyDerivation.Argon2i:
                    hasher = new Argon2i(passphrase);
                    break;
                case KeyDerivation.Argon2d:
                    hasher = new Argon2d(passphrase);
                    break;
                case KeyDerivation.Argon2id:
                    hasher = new Argon2id(passphrase);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            hasher.MemorySize = (int)fileData.kdfParameters[argonMemoryKey];
            hasher.Iterations = (int)fileData.kdfParameters[argonPassesKey];
            hasher.DegreeOfParallelism = (int)fileData.kdfParameters[argonParallelismKey];
            hasher.Salt = (byte[])fileData.kdfParameters[argonSaltKey];

            // These values are copied by Aes and HMACSHA256 which
            // means they aren't explicitly zeroed unless we do it.
            // and then cipher.Clear() and mac.Clear() need to be
            // called once they're no longer in use.
            var kdf = hasher.GetBytes(cipherLength + ivLength + macLength);
            cipherKey = kdf.Skip(0).Take(cipherLength).ToArray();
            iv = kdf.Skip(cipherLength).Take(ivLength).ToArray();
            macKey = kdf.Skip(cipherLength + ivLength).Take(macLength).ToArray();
        }

        private static void DecryptPrivateKey(ref FileData fileData)
        {
            switch (fileData.privateKeyAlgorithm)
            {
                case PrivateKeyAlgorithm.None:
                    return;

                case PrivateKeyAlgorithm.AES256_CBC:

                    /* create key from passphrase */

                    byte[] cipherKey;
                    byte[] iv;

                    switch (fileData.ppkFileVersion)
                    {
                        case Version.V1:
                        case Version.V2:
                            var sha = SHA1.Create();
                            sha.Initialize();
                            var key = new List<byte>();
                            iv = new byte[16];

                            var hashData = new byte[
                                cPrivateKeyDecryptSalt1.Length + fileData.passphrase.Length
                            ];

                            Array.Copy(
                                Encoding.UTF8.GetBytes(cPrivateKeyDecryptSalt1),
                                hashData,
                                cPrivateKeyDecryptSalt1.Length
                            );

                            var passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(
                                fileData.passphrase
                            );

                            for (var i = 0; i < fileData.passphrase.Length; i++)
                            {
                                int unicodeChar = Marshal.ReadInt16(passphrasePtr + i * 2);
                                var ansiChar = Util.UnicodeToAnsi(unicodeChar);
                                hashData[cPrivateKeyDecryptSalt1.Length + i] = ansiChar;
                                Marshal.WriteByte(passphrasePtr, i, 0);
                            }

                            Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
                            sha.ComputeHash(hashData);
                            key.AddRange(sha.Hash);

                            Array.Copy(
                                Encoding.UTF8.GetBytes(cPrivateKeyDecryptSalt2),
                                hashData,
                                cPrivateKeyDecryptSalt2.Length
                            );

                            sha.ComputeHash(hashData);
                            key.AddRange(sha.Hash);
                            var keySize = 256 / 8; // convert bits to bytes
                            key.RemoveRange(keySize, key.Count - keySize); // remove extra bytes
                            cipherKey = key.ToArray();

                            sha.Clear();
                            break;
                        case Version.V3:
                            byte[] macKey;
                            argonKeys(fileData, out cipherKey, out iv, out macKey);
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }

                    /* decrypt private key */

                    var aes = Aes.Create();
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    aes.Key = cipherKey;
                    Array.Clear(cipherKey, 0, cipherKey.Length);
                    aes.IV = iv;
                    var decryptor = aes.CreateDecryptor();
                    fileData.privateKeyBlob = Util.GenericTransform(
                        decryptor,
                        fileData.privateKeyBlob
                    );
                    decryptor.Dispose();
                    aes.Clear();
                    break;

                default:
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.PrivateKeyEncryption
                    );
            }
        }

        private static void VerifyIntegrity(FileData fileData)
        {
            var builder = new BlobBuilder();
            if (fileData.ppkFileVersion != Version.V1)
            {
                builder.AddStringBlob(fileData.publicKeyAlgorithm.GetIdentifier());
                builder.AddStringBlob(fileData.privateKeyAlgorithm.GetIdentifierString());
                builder.AddBlob(Encoding.GetEncoding(1252).GetBytes(fileData.comment));
                builder.AddBlob(fileData.publicKeyBlob);
                builder.AddInt(fileData.privateKeyBlob.Length);
            }
            builder.AddBytes(fileData.privateKeyBlob);

            byte[] computedHash;
            switch (fileData.ppkFileVersion)
            {
                case Version.V1:
                case Version.V2:
                    var sha = SHA1.Create();
                    if (fileData.isHMAC)
                    {
                        var hmac = HMACSHA1.Create();
                        if (fileData.passphrase != null)
                        {
                            var hashData = new byte[
                                cMACKeySalt.Length + fileData.passphrase.Length
                            ];

                            Array.Copy(
                                Encoding.UTF8.GetBytes(cMACKeySalt),
                                hashData,
                                cMACKeySalt.Length
                            );

                            var passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(
                                fileData.passphrase
                            );

                            for (var i = 0; i < fileData.passphrase.Length; i++)
                            {
                                int unicodeChar = Marshal.ReadInt16(passphrasePtr + i * 2);
                                var ansiChar = Util.UnicodeToAnsi(unicodeChar);
                                hashData[cMACKeySalt.Length + i] = ansiChar;
                                Marshal.WriteByte(passphrasePtr, i * 2, 0);
                            }

                            Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
                            hmac.Key = sha.ComputeHash(hashData);
                        }
                        else
                        {
                            hmac.Key = sha.ComputeHash(Encoding.UTF8.GetBytes(cMACKeySalt));
                        }
                        computedHash = hmac.ComputeHash(builder.GetBlob());
                        hmac.Clear();
                    }
                    else
                    {
                        computedHash = sha.ComputeHash(builder.GetBlob());
                    }
                    sha.Clear();
                    builder.Clear();

                    break;
                case Version.V3:
                    byte[] cipherKey,
                        iv,
                        macKey;
                    argonKeys(fileData, out cipherKey, out iv, out macKey);
                    var hmacsha256 = new HMACSHA256(macKey);
                    computedHash = hmacsha256.ComputeHash(builder.GetBlob());
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            try
            {
                if (!fileData.privateMAC.SequenceEqual(computedHash))
                {
                    // private key data should start with 3 bytes with value 0 if it was
                    // properly decrypted or does not require decryption
                    if (
                        (fileData.privateKeyBlob[0] == 0)
                        && (fileData.privateKeyBlob[1] == 0)
                        && (fileData.privateKeyBlob[2] == 0)
                    )
                    {
                        // so if they bytes are there, passphrase decrypted properly and
                        // something else is wrong with the file contents
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.FileCorrupt
                        );
                    }
                    else
                    {
                        // if the bytes are not zeros, we assume that the data was not
                        // properly decrypted because the passphrase was incorrect.
                        throw new PpkFormatterException(
                            PpkFormatterException.PpkErrorType.BadPassphrase
                        );
                    }
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                Array.Clear(computedHash, 0, computedHash.Length);
            }
        }

        private static AsymmetricCipherKeyPair CreateCipherKeyPair(
            PublicKeyAlgorithm algorithm,
            byte[] publicKeyBlob,
            byte[] privateKeyBlob
        )
        {
            var parser = new BlobParser(publicKeyBlob);
            OpensshCertificate cert;
            var publicKey = parser.ReadSsh2PublicKeyData(out cert);
            parser = new BlobParser(privateKeyBlob);

            switch (algorithm)
            {
                case PublicKeyAlgorithm.SshRsa:
                    var rsaPublicKeyParams = (RsaKeyParameters)publicKey;

                    var d = new BigInteger(1, parser.ReadBlob());
                    var p = new BigInteger(1, parser.ReadBlob());
                    var q = new BigInteger(1, parser.ReadBlob());
                    var inverseQ = new BigInteger(1, parser.ReadBlob());

                    /* compute missing parameters */
                    var dp = d.Remainder(p.Subtract(BigInteger.One));
                    var dq = d.Remainder(q.Subtract(BigInteger.One));

                    var rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
                        rsaPublicKeyParams.Modulus,
                        rsaPublicKeyParams.Exponent,
                        d,
                        p,
                        q,
                        dp,
                        dq,
                        inverseQ
                    );

                    return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);

                case PublicKeyAlgorithm.SshDss:
                    var dsaPublicKeyParams = (DsaPublicKeyParameters)publicKey;

                    var x = new BigInteger(1, parser.ReadBlob());
                    var dsaPrivateKeyParams = new DsaPrivateKeyParameters(
                        x,
                        dsaPublicKeyParams.Parameters
                    );

                    return new AsymmetricCipherKeyPair(dsaPublicKeyParams, dsaPrivateKeyParams);
                case PublicKeyAlgorithm.SshEd25519:
                    var ed25596PublicKey = (Ed25519PublicKeyParameters)publicKey;

                    var privBlob = parser.ReadBlob();
                    var ed25596PrivateKey = new Ed25519PrivateKeyParameters(privBlob);

                    return new AsymmetricCipherKeyPair(ed25596PublicKey, ed25596PrivateKey);
                case PublicKeyAlgorithm.EcdsaSha2Nistp256:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521:
                    var ecPublicKeyParams = (ECPublicKeyParameters)publicKey;

                    var ecdsaPrivate = new BigInteger(1, parser.ReadBlob());
                    var ecPrivateKeyParams = new ECPrivateKeyParameters(
                        ecdsaPrivate,
                        ecPublicKeyParams.Parameters
                    );

                    return new AsymmetricCipherKeyPair(ecPublicKeyParams, ecPrivateKeyParams);
                default:
                    // unsupported encryption algorithm
                    throw new PpkFormatterException(
                        PpkFormatterException.PpkErrorType.PublicKeyEncryption
                    );
            }
        }

        #endregion -- Private Methods --

    }

    public enum KeyDerivation
    {
        Argon2id,
        Argon2i,
        Argon2d,
    }

    static class PpkFormatterExt
    {
        public static string GetIdentifierString(this PpkFormatter.PrivateKeyAlgorithm aAlgorithm)
        {
            switch (aAlgorithm)
            {
                case PpkFormatter.PrivateKeyAlgorithm.None:
                    return PpkFormatter.ALGORITHM_NONE;
                case PpkFormatter.PrivateKeyAlgorithm.AES256_CBC:
                    return PpkFormatter.ALGORITHM_AES256_CBC;
                default:
                    Debug.Fail("Unknown algorithm");
                    throw new Exception("Unknown algorithm");
            }
        }

        public static bool TryParsePrivateKeyAlgorithm(
            this string aString,
            ref PpkFormatter.PrivateKeyAlgorithm aAlgorithm
        )
        {
            switch (aString)
            {
                case PpkFormatter.ALGORITHM_NONE:
                    aAlgorithm = PpkFormatter.PrivateKeyAlgorithm.None;
                    return true;
                case PpkFormatter.ALGORITHM_AES256_CBC:
                    aAlgorithm = PpkFormatter.PrivateKeyAlgorithm.AES256_CBC;
                    return true;
                default:
                    return false;
            }
        }

        public static string GetName(this PpkFormatter.Version aVersion)
        {
            switch (aVersion)
            {
                case PpkFormatter.Version.V1:
                    return "1";
                case PpkFormatter.Version.V2:
                    return "2";
                case PpkFormatter.Version.V3:
                    return "3";
                default:
                    Debug.Fail("Unknown version");
                    throw new Exception("Unknown version");
            }
        }

        public static bool TryParseVersion(this string text, ref PpkFormatter.Version version)
        {
            switch (text)
            {
                case "1":
                    version = PpkFormatter.Version.V1;
                    return true;
                case "2":
                    version = PpkFormatter.Version.V2;
                    return true;
                case "3":
                    version = PpkFormatter.Version.V3;
                    return true;
                default:
                    return false;
            }
        }
    }
}
