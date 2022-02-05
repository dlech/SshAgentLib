//
// Ssh1KeyFormatter.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2013 David Lechner
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
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Formats SSH1 public keys
    /// </summary>
    public class Ssh1KeyFormatter : KeyFormatter
    {
        public const string FILE_HEADER_LINE = "SSH PRIVATE KEY FILE FORMAT 1.1";
        public const int SSH_CIPHER_NONE = 0;
        public const int SSH_CIPHER_3DES = 3;

        public override void Serialize(Stream aStream, object aObject)
        {
            /* check for required parameters */
            if (aStream == null)
            {
                throw new ArgumentNullException("aStream");
            }

            if (aObject == null)
            {
                throw new ArgumentNullException("aObject");
            }

            PasswordFinder pwFinder = null;
            if (GetPassphraseCallbackMethod != null)
            {
                pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
            }

            var passphrase = pwFinder?.GetPassword();

            byte cipherType;
            if (passphrase == null || passphrase.Length == 0)
            {
                cipherType = SSH_CIPHER_NONE;
            }
            else
            {
                cipherType = SSH_CIPHER_3DES;
            }

            var builder = new BlobBuilder();

            var sshKey = aObject as ISshKey;
            var publicKeyParams = sshKey.GetPublicKeyParameters() as RsaKeyParameters;
            var privateKeyParams = sshKey.GetPrivateKeyParameters() as RsaPrivateCrtKeyParameters;

            /* writing info headers */
            builder.AddBytes(Encoding.ASCII.GetBytes(FILE_HEADER_LINE + "\n"));
            builder.AddUInt8(0); //end of string
            builder.AddUInt8(cipherType); //cipher
            builder.AddInt(0); //reserved

            /* writing public key */
            builder.AddInt(sshKey.Size);
            builder.AddSsh1BigIntBlob(publicKeyParams.Modulus);
            builder.AddSsh1BigIntBlob(publicKeyParams.Exponent);
            builder.AddStringBlob(sshKey.Comment);

            /* writing private key */
            var privateKeyBuilder = new BlobBuilder();

            /* adding some control values */
            var random = new Random();
            var resultCheck = new byte[2];
            random.NextBytes(resultCheck);

            privateKeyBuilder.AddUInt8(resultCheck[0]);
            privateKeyBuilder.AddUInt8(resultCheck[1]);
            privateKeyBuilder.AddUInt8(resultCheck[0]);
            privateKeyBuilder.AddUInt8(resultCheck[1]);
            privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.Exponent);
            privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.DQ);
            privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.P);
            privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.Q);

            if (cipherType == SSH_CIPHER_NONE)
            {
                /* plain-text */
                builder.AddBytes(privateKeyBuilder.GetBlob());
            }
            else
            {
                byte[] keydata;
                using (var md5 = MD5.Create())
                {
                    keydata = md5.ComputeHash(Encoding.ASCII.GetBytes(passphrase));
                }

                /* encryption */
                var desEngine = new DesSsh1Engine();
                desEngine.Init(true, new KeyParameter(keydata));

                var bufferedBlockCipher = new BufferedBlockCipher(desEngine);
                var ouputBuffer = bufferedBlockCipher.ProcessBytes(privateKeyBuilder.GetBlob());

                builder.AddBytes(ouputBuffer);
            }

            /* writing result to file */
            var builderOutput = builder.GetBlob();
            aStream.Write(builderOutput, 0, builderOutput.Length);
            aStream.Close();
        }

        public override object Deserialize(Stream aStream)
        {
            /* check for required parameters */
            if (aStream == null)
            {
                throw new ArgumentNullException("aStream");
            }

            /* reading unencrypted part */
            var parser = new BlobParser(aStream);

            parser.ReadBytes(FILE_HEADER_LINE.Length + 2); //Skipping header line

            var cipherType = parser.ReadByte();
            if (cipherType != SSH_CIPHER_3DES && cipherType != SSH_CIPHER_NONE)
            {
                //TripleDes is the only encryption supported
                throw new KeyFormatterException("Unsupported cypherType: " + cipherType);
            }

            parser.ReadUInt32(); //reserved

            /* reading public key */
            var aPublicKeyParameter = parser.ReadSsh1PublicKeyData(false);
            var keyComment = parser.ReadString();

            /* reading private key */
            var inputBuffer = new byte[aStream.Length];
            aStream.Read(inputBuffer, 0, inputBuffer.Length);
            byte[] outputBuffer;

            try
            {
                if (cipherType == 3)
                {
                    /* private key is 3DES encrypted */
                    PasswordFinder pwFinder = null;
                    if (GetPassphraseCallbackMethod != null)
                    {
                        pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
                    }

                    byte[] keydata;
                    try
                    {
                        using (var md5 = MD5.Create())
                        {
                            var md5Buffer = pwFinder.GetPassword();
                            keydata = md5.ComputeHash(Encoding.ASCII.GetBytes(md5Buffer));
                        }
                    }
                    catch (PasswordException ex)
                    {
                        if (GetPassphraseCallbackMethod == null)
                        {
                            throw new CallbackNullException();
                        }
                        throw new KeyFormatterException("see inner exception", ex);
                    }

                    /* decryption */
                    var desEngine = new DesSsh1Engine();
                    desEngine.Init(false, new KeyParameter(keydata));

                    var bufferedBlockCipher = new BufferedBlockCipher(desEngine);
                    outputBuffer = bufferedBlockCipher.ProcessBytes(inputBuffer);
                }
                else
                {
                    /* private key is stored in plain text */
                    outputBuffer = inputBuffer;
                }

                var privateKeyParser = new BlobParser(outputBuffer);

                /* checking result of decryption */
                var resultCheck = privateKeyParser.ReadBytes(4);
                if (resultCheck[0] != resultCheck[2] || resultCheck[1] != resultCheck[3])
                {
                    throw new KeyFormatterException("bad passphrase");
                }

                /* reading private key */
                var keyPair = privateKeyParser.ReadSsh1KeyData(aPublicKeyParameter);
                var key = new SshKey(SshVersion.SSH1, keyPair, keyComment);
                return key;
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

        private class PasswordFinder : IPasswordFinder
        {
            private GetPassphraseCallback mCallback;

            public PasswordFinder(GetPassphraseCallback aCallback)
            {
                mCallback = aCallback;
            }

            public char[] GetPassword()
            {
                var passphrase = mCallback.Invoke(null);
                var passwordChars = new char[passphrase.Length];
                var passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(passphrase);
                for (var i = 0; i < passphrase.Length; i++)
                {
                    passwordChars[i] = (char)Marshal.ReadInt16(passphrasePtr, i * 2);
                }
                Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
                return passwordChars;
            }
        }
    }
}
