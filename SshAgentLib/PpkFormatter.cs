//
// Ppkformatter.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013 David Lechner
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
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using dlech.SshAgentLib.Crypto;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

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
      V2
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

      /// <summary>
      /// The private key.
      /// </summary>
      public PinnedArray<byte> privateKeyBlob;

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
    public override object Deserialize(Stream aStream)
    {
      FileData fileData = new FileData();

      /* check for required parameters */
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }

      string line;
      string[] pair = new string[2];
      int lineCount, i;

      StreamReader reader = new StreamReader(aStream, Encoding.GetEncoding(1252));
      char[] delimArray = { cDelimeter };

      try {
        /* read file version */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (!pair[0].StartsWith(puttyUserKeyFileKey)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          puttyUserKeyFileKey + " expected");
        }
        string ppkFileVersion = pair[0].Remove(0, puttyUserKeyFileKey.Length);
        if (!ppkFileVersion.TryParseVersion(ref fileData.ppkFileVersion)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileVersion);
        }
        if (fileData.ppkFileVersion == Version.V1) {
          if (WarnOldFileFormatCallbackMethod != null) {
            WarnOldFileFormatCallbackMethod.Invoke();
          }
        }

        /* read public key encryption algorithm type */
        string algorithm = pair[1].Trim();
        if (!algorithm.TryParsePublicKeyAlgorithm(ref fileData.publicKeyAlgorithm)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PublicKeyEncryption);
        }

        /* read private key encryption algorithm type */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != privateKeyEncryptionKey) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          privateKeyEncryptionKey + " expected");
        }
        algorithm = pair[1].Trim();
        if (!algorithm.TryParsePrivateKeyAlgorithm(ref fileData.privateKeyAlgorithm)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PrivateKeyEncryption);
        }

        /* read comment */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != commentKey) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          commentKey + " expected");
        }
        fileData.comment = pair[1].Trim();

        /* read public key */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != publicKeyLinesKey) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          publicKeyLinesKey + " expected");
        }
        if (!int.TryParse(pair[1], out lineCount)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          "integer expected");
        }
        string publicKeyString = string.Empty;
        for (i = 0; i < lineCount; i++) {
          publicKeyString += reader.ReadLine();
        }
        fileData.publicKeyBlob = Util.FromBase64(publicKeyString);

        /* read private key */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != privateKeyLinesKey) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          privateKeyLinesKey + " expected");
        }
        if (!int.TryParse(pair[1], out lineCount)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                          "integer expected");
        }
        string privateKeyString = string.Empty;
        for (i = 0; i < lineCount; i++) {
          privateKeyString += reader.ReadLine();
        }
        fileData.privateKeyBlob =
          new PinnedArray<byte>(Util.FromBase64(privateKeyString));

        /* read MAC */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != privateMACKey) {
          fileData.isHMAC = false;
          if (pair[0] != privateHashKey || fileData.ppkFileVersion != Version.V1) {
            throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                            privateMACKey + " expected");
          }
        } else {
          fileData.isHMAC = true;
        }
        string privateMACString = pair[1].Trim();
        fileData.privateMAC = Util.FromHex(privateMACString);


        /* get passphrase and decrypt private key if required */
        if (fileData.privateKeyAlgorithm != PrivateKeyAlgorithm.None) {
          if (GetPassphraseCallbackMethod == null) {
            throw new CallbackNullException();
          }
          fileData.passphrase = GetPassphraseCallbackMethod.Invoke(fileData.comment);
          DecryptPrivateKey(ref fileData);
        }

        VerifyIntegrity(fileData);

        AsymmetricCipherKeyPair cipherKeyPair =
          CreateCipherKeyPair(fileData.publicKeyAlgorithm,
          fileData.publicKeyBlob, fileData.privateKeyBlob.Data);
        SshKey key = new SshKey(SshVersion.SSH2, cipherKeyPair, fileData.comment);
        return key;

      } catch (PpkFormatterException) {
        throw;
      } catch (CallbackNullException) {
        throw;
      } catch (Exception ex) {
        throw new PpkFormatterException(
            PpkFormatterException.PpkErrorType.FileFormat,
            "See inner exception.", ex);
      } finally {
        if (fileData.publicKeyBlob != null) {
          Array.Clear(fileData.publicKeyBlob, 0, fileData.publicKeyBlob.Length);
        }
        if (fileData.privateKeyBlob != null) {
          fileData.privateKeyBlob.Dispose();
        }
        if (fileData.privateMAC != null) {
          Array.Clear(fileData.privateMAC, 0, fileData.privateMAC.Length);
        }
        reader.Close();
      }
    }

    #endregion -- Public Methods --


    #region -- Private Methods --

    private static void DecryptPrivateKey(ref FileData fileData)
    {
      switch (fileData.privateKeyAlgorithm) {

        case PrivateKeyAlgorithm.None:
          return;

        case PrivateKeyAlgorithm.AES256_CBC:

          /* create key from passphrase */

          SHA1 sha = SHA1.Create();
          sha.Initialize();
          List<byte> key = new List<byte>();

          using (PinnedArray<byte> hashData =
                 new PinnedArray<byte>(cPrivateKeyDecryptSalt1.Length +
                                     fileData.passphrase.Length)) {
            Array.Copy(Encoding.UTF8.GetBytes(cPrivateKeyDecryptSalt1),
                       hashData.Data, cPrivateKeyDecryptSalt1.Length);
            IntPtr passphrasePtr =
              Marshal.SecureStringToGlobalAllocUnicode(fileData.passphrase);
            for (int i = 0; i < fileData.passphrase.Length; i++) {
              int unicodeChar = Marshal.ReadInt16(passphrasePtr + i * 2);
              byte ansiChar = Util.UnicodeToAnsi(unicodeChar);
              hashData.Data[cPrivateKeyDecryptSalt1.Length + i] = ansiChar;
              Marshal.WriteByte(passphrasePtr, i, 0);
            }
            Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
            sha.ComputeHash(hashData.Data);
            key.AddRange(sha.Hash);
            Array.Copy(Encoding.UTF8.GetBytes(cPrivateKeyDecryptSalt2),
                       hashData.Data, cPrivateKeyDecryptSalt2.Length);
            sha.ComputeHash(hashData.Data);
            key.AddRange(sha.Hash);
          }
          sha.Clear();
          /* decrypt private key */

          Aes aes = Aes.Create();
          aes.KeySize = 256;
          aes.Mode = CipherMode.CBC;
          aes.Padding = PaddingMode.None;
          int keySize = aes.KeySize / 8; // convert bits to bytes
          key.RemoveRange(keySize, key.Count - keySize); // remove extra bytes
          aes.Key = key.ToArray();
          Util.ClearByteList(key);
          aes.IV = new byte[aes.IV.Length];
          ICryptoTransform decryptor = aes.CreateDecryptor();
          fileData.privateKeyBlob.Data =
            Util.GenericTransform(decryptor, fileData.privateKeyBlob.Data);
          decryptor.Dispose();
          aes.Clear();
          break;

        default:
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PrivateKeyEncryption);
      }
    }

    private static void VerifyIntegrity(FileData fileData)
    {

      BlobBuilder builder = new BlobBuilder();
      if (fileData.ppkFileVersion != Version.V1) {
        builder.AddStringBlob(fileData.publicKeyAlgorithm.GetIdentifierString());
        builder.AddStringBlob(fileData.privateKeyAlgorithm.GetIdentifierString());
        builder.AddBlob(Encoding.GetEncoding(1252).GetBytes(fileData.comment));
        builder.AddBlob(fileData.publicKeyBlob);
        builder.AddInt(fileData.privateKeyBlob.Data.Length);
      }
      builder.AddBytes(fileData.privateKeyBlob.Data);

      byte[] computedHash;
      SHA1 sha = SHA1.Create();
      if (fileData.isHMAC) {
        HMAC hmac = HMACSHA1.Create();
        if (fileData.passphrase != null) {
          using (PinnedArray<byte> hashData =
                 new PinnedArray<byte>(cMACKeySalt.Length +
                   fileData.passphrase.Length)) {
            Array.Copy(Encoding.UTF8.GetBytes(cMACKeySalt),
                       hashData.Data, cMACKeySalt.Length);
            IntPtr passphrasePtr =
              Marshal.SecureStringToGlobalAllocUnicode(fileData.passphrase);
            for (int i = 0; i < fileData.passphrase.Length; i++) {
              int unicodeChar = Marshal.ReadInt16(passphrasePtr + i * 2);
              byte ansiChar = Util.UnicodeToAnsi(unicodeChar);
              hashData.Data[cMACKeySalt.Length + i] = ansiChar;
              Marshal.WriteByte(passphrasePtr, i * 2, 0);
            }
            Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
            hmac.Key = sha.ComputeHash(hashData.Data);
          }
        } else {
          hmac.Key = sha.ComputeHash(Encoding.UTF8.GetBytes(cMACKeySalt));
        }
        computedHash = hmac.ComputeHash(builder.GetBlob());
        hmac.Clear();
      } else {
        computedHash = sha.ComputeHash(builder.GetBlob());
      }
      sha.Clear();
      builder.Clear();

      try {
        int macLength = computedHash.Length;
        bool failed = false;
        if (fileData.privateMAC.Length == macLength) {
          for (int i = 0; i < macLength; i++) {
            if (fileData.privateMAC[i] != computedHash[i]) {
              failed = true;
              break;
            }
          }
        } else {
          failed = true;
        }
        if (failed) {
          // private key data should start with 3 bytes with value 0 if it was
          // properly decrypted or does not require decryption
          if ((fileData.privateKeyBlob.Data[0] == 0) &&
              (fileData.privateKeyBlob.Data[1] == 0) &&
              (fileData.privateKeyBlob.Data[2] == 0)) {
            // so if they bytes are there, passphrase decrypted properly and
            // something else is wrong with the file contents
            throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileCorrupt);
          } else {
            // if the bytes are not zeros, we assume that the data was not
            // properly decrypted because the passphrase was incorrect.
            throw new PpkFormatterException(PpkFormatterException.PpkErrorType.BadPassphrase);
          }
        }
      } catch {
        throw;
      } finally {
        Array.Clear(computedHash, 0, computedHash.Length);
      }
    }

    private static AsymmetricCipherKeyPair CreateCipherKeyPair(
      PublicKeyAlgorithm aAlgorithm,
      byte[] aPublicKeyBlob, byte[] aPrivateKeyBlob)
    {
      BigInteger exponent, modulus, d, p, q, inverseQ, dp, dq; // RSA params
      BigInteger /* p, q, */ g, y, x; // DSA params

      BlobParser parser = new BlobParser(aPublicKeyBlob);
      BlobParser privateParser = new BlobParser(aPrivateKeyBlob);
      string algorithm = parser.ReadString();
      if (algorithm != aAlgorithm.GetIdentifierString()) {
        throw new InvalidOperationException("public key is not " +
          aAlgorithm.GetIdentifierString());
      }

      switch (aAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:

          /* read parameters that were stored in file */

          exponent = new BigInteger(1, parser.ReadBlob());
          modulus = new BigInteger(1, parser.ReadBlob());

          parser = new BlobParser(aPrivateKeyBlob);
          d = new BigInteger(1, parser.ReadBlob());
          p = new BigInteger(1, parser.ReadBlob());
          q = new BigInteger(1, parser.ReadBlob());
          inverseQ = new BigInteger(1, parser.ReadBlob());
          //parser.MoveNext();

          /* compute missing parameters */
          dp = d.Remainder(p.Subtract(BigInteger.One));
          dq = d.Remainder(q.Subtract(BigInteger.One));

          RsaKeyParameters rsaPublicKeyParams =
            new RsaKeyParameters(false, modulus, exponent);
          RsaPrivateCrtKeyParameters rsaPrivateKeyParams =
            new RsaPrivateCrtKeyParameters(modulus, exponent, d, p, q, dp, dq,
              inverseQ);

          return new AsymmetricCipherKeyPair(rsaPublicKeyParams,
            rsaPrivateKeyParams);

        case PublicKeyAlgorithm.SSH_DSS:

          /* read parameters that were stored in file */

          p = new BigInteger(1, parser.ReadBlob());
          q = new BigInteger(1, parser.ReadBlob());
          g = new BigInteger(1, parser.ReadBlob());
          y = new BigInteger(1, parser.ReadBlob());
          //parser.MoveNext();

          parser = new BlobParser(aPrivateKeyBlob);
          x = new BigInteger(1, parser.ReadBlob());

          DsaParameters commonParams = new DsaParameters(p, q, g);
          DsaPublicKeyParameters dsaPublicKeyParams =
            new DsaPublicKeyParameters(y, commonParams);
          DsaPrivateKeyParameters dsaPrivateKeyParams =
            new DsaPrivateKeyParameters(x, commonParams);

          return new AsymmetricCipherKeyPair(dsaPublicKeyParams,
            dsaPrivateKeyParams);
        case PublicKeyAlgorithm.ED25519:
          byte[] pubBlob = parser.ReadBlob();
          byte[] privBlob = privateParser.ReadBlob();
          byte[] privSig = new byte[64];
          // OpenSSH's "private key" is actually the private key with the public key tacked on ...
          Buffer.BlockCopy(privBlob, 0, privSig, 0, 32);
          Buffer.BlockCopy(pubBlob, 0, privSig, 32, 32);
          return new AsymmetricCipherKeyPair(new Ed25519PublicKeyParameter(pubBlob), new Ed25519PrivateKeyParameter(privSig));
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
          var ecdsaPrivate = new BigInteger(1, privateParser.ReadBlob());
          parser.Stream.Seek(0, SeekOrigin.Begin);
          ECPublicKeyParameters ecPublicKeyParams = (ECPublicKeyParameters) parser.ReadSsh2PublicKeyData();
          ECPrivateKeyParameters ecPrivateKeyParams = new ECPrivateKeyParameters(ecdsaPrivate, ecPublicKeyParams.Parameters);
          return new AsymmetricCipherKeyPair(ecPublicKeyParams, ecPrivateKeyParams);
        default:
          // unsupported encryption algorithm
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PublicKeyEncryption);
      }
    }

    # endregion -- Private Methods --

  }

  internal static class PpkFormatterExt
  {
    public static string GetIdentifierString(
      this PpkFormatter.PrivateKeyAlgorithm aAlgorithm)
    {
      switch (aAlgorithm) {
        case PpkFormatter.PrivateKeyAlgorithm.None:
          return PpkFormatter.ALGORITHM_NONE;
        case PpkFormatter.PrivateKeyAlgorithm.AES256_CBC:
          return PpkFormatter.ALGORITHM_AES256_CBC;
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }

    public static bool TryParsePrivateKeyAlgorithm(this string aString,
      ref PpkFormatter.PrivateKeyAlgorithm aAlgorithm)
    {
      switch (aString) {
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
      switch (aVersion) {
        case PpkFormatter.Version.V1:
          return "1";
        case PpkFormatter.Version.V2:
          return "2";
        default:
          Debug.Fail("Unknown version");
          throw new Exception("Unknown version");
      }
    }

    public static bool TryParseVersion(
      this string aString, ref PpkFormatter.Version aVersion)
    {
      switch (aString) {
        case "1":
          aVersion = PpkFormatter.Version.V1;
          return true;
        case "2":
          aVersion = PpkFormatter.Version.V2;
          return true;
        default:
          return false;
      }
    }

    public static bool TryParsePublicKeyAlgorithm(this string aString,
      ref PublicKeyAlgorithm aAlgorithm)
    {
      switch (aString) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY:
          aAlgorithm = PublicKeyAlgorithm.SSH_RSA;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY:
          aAlgorithm = PublicKeyAlgorithm.SSH_DSS;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_KEY:
          aAlgorithm = PublicKeyAlgorithm.ECDSA_SHA2_NISTP256;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_KEY:
          aAlgorithm = PublicKeyAlgorithm.ECDSA_SHA2_NISTP384;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_KEY:
          aAlgorithm = PublicKeyAlgorithm.ECDSA_SHA2_NISTP521;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ED25519:
          aAlgorithm = PublicKeyAlgorithm.ED25519;
          return true;
        default:
          return false;
      }
    }

  }
}

