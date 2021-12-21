//
// Ppkformatter.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013,2015,2017 David Lechner
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
using System.Text.RegularExpressions;
using dlech.SshAgentLib.Crypto;
using Konscious.Security.Cryptography;
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
    public static readonly string cLegalVersions = Util.EnumJoin<Version>("|").Replace("V", "");

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
    public const string puttyUserKeyFileKey = "PuTTY-User-Key-File-";

    /// <summary>
    /// Key that indicates the line containing the private key encryption algorithm
    /// </summary>
    private const string privateKeyEncryptionKey = "Encryption";

    private const int cipherLength = 32;
    private const int ivLength = 16;
    private const int macLength = 32;

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
    /// Key that indicates the key derivation algorithm
    /// </summary>
    private const string keyDeriviationKey = "Key-Derivation";

    /// <summary>
    /// Argon2 memory
    /// </summary>
    private const string argonMemoryKey = "Argon2-Memory";

    /// <summary>
    /// Argon2 iterations
    /// </summary>
    private const string argonPassesKey = "Argon2-Passes";

    /// <summary>
    /// Argon2 parallelism
    /// </summary>
    private const string argonParallelismKey = "Argon2-Parallelism";

    /// <summary>
    /// Argon2 salt represented as a hex encoded byte[] is the ppk file
    /// </summary>
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
      V3
    }

    /// <summary>
    /// Valid private key encryption algorithms
    /// </summary>
    internal enum PrivateKeyAlgorithm
    {
      None,
      AES256_CBC
    }

    internal enum KeyDerivation
    {
      Argon2i,
      Argon2d,
      Argon2id
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
      /// Key Derivation algorithm usually Argon2
      /// </summary>
      public KeyDerivation kdfAlgorithm;

      /// <summary>
      /// key value pairs for various kdf algorithms
      /// for Argon2 the parameters Argon2-Memory, Argon2-Passes, Argon2-Parallelism
      /// will have an "int" type for their value and Argon2-Salt will have a "byte[]" type for it's value
      /// </summary>
      public Dictionary<string, object> kdfParameters;

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
      int lineCount;
      Match m;

      StreamReader reader = new StreamReader(aStream, Encoding.GetEncoding(1252));

      try {
        /* read file version */
        line = reader.ReadLine();
        m = MatchOrThrow(line, "^"+puttyUserKeyFileKey+"("+cLegalVersions+"): ?(.*)$");

        fileData.ppkFileVersion = Util.EnumParse<Version>("V"+m.Groups[1].Value);
        if (fileData.ppkFileVersion == Version.V1) {
          WarnOldFileFormatCallbackMethod?.Invoke();
        }

        /* read public key encryption algorithm type */
        if (!m.Groups[2].Value.TryParsePublicKeyAlgorithm(ref fileData.publicKeyAlgorithm)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PublicKeyEncryption);
        }

        /* read private key encryption algorithm type */
        line = reader.ReadLine();
        m = MatchOrThrow(line, "^"+privateKeyEncryptionKey+": ?(.*)$");
        if (!m.Groups[1].Value.TryParsePrivateKeyAlgorithm(ref fileData.privateKeyAlgorithm)) {
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PrivateKeyEncryption);
        }

        /* read comment */
        line = reader.ReadLine();
        m = MatchOrThrow(line, "^"+commentKey+": ?(.*)$");
        fileData.comment = m.Groups[1].Value;

        /* read public key */
        line = reader.ReadLine();
        // match 1 <= N < 100000 and throw away leading zeros
        m = MatchOrThrow(line, "^"+publicKeyLinesKey+": 0*([1-9][0-9]{0,4})$");

        lineCount = int.Parse(m.Groups[1].Value);
        string publicKeyString = string.Join("", from v in Enumerable.Range(0, lineCount) select reader.ReadLine());
        fileData.publicKeyBlob = Util.FromBase64(publicKeyString);

        /* key derivation function */
        if (fileData.privateKeyAlgorithm != PrivateKeyAlgorithm.None && fileData.ppkFileVersion >= Version.V3) {
          line = reader.ReadLine();
          string legal = Util.EnumJoin<KeyDerivation>("|");
          m = MatchOrThrow(line, "^"+keyDeriviationKey+": ?("+legal+")$");

          fileData.kdfAlgorithm = Util.EnumParse<KeyDerivation>(m.Groups[1].Value);

          string kdfName = Enum.GetName(typeof(KeyDerivation), fileData.kdfAlgorithm);
          fileData.kdfParameters = new Dictionary<string, object>();
          if (kdfName.StartsWith("Argon2")) {
            foreach (var paramKey in new[]{argonMemoryKey, argonPassesKey, argonParallelismKey}) {
              line = reader.ReadLine();
              m = MatchOrThrow(line, "^("+paramKey+"): 0*([1-9][0-9]{0,8})$");
              fileData.kdfParameters[m.Groups[1].Value] = int.Parse(m.Groups[2].Value);
            }

            line = reader.ReadLine();
            m = MatchOrThrow(line, "^("+argonSaltKey+"): ([0-9a-fA-F]+)$");
            fileData.kdfParameters[m.Groups[1].Value] = Util.FromHex(m.Groups[2].Value);
          }
          else {
            throw new PpkFormatterException(
              PpkFormatterException.PpkErrorType.FileFormat, "cannot get kdf parameters for algorithm: "+kdfName);
          }
        }


        /* read private key */
        line = reader.ReadLine();
        // match 1 <= N < 100000 and throw away leading zeros
        m = MatchOrThrow(line, "^"+privateKeyLinesKey+": 0*([1-9][0-9]{0,4})$");
        lineCount = int.Parse(m.Groups[1].Value);
        string privateKeyString = string.Join("", from v in Enumerable.Range(0, lineCount) select reader.ReadLine());
        fileData.privateKeyBlob = new PinnedArray<byte>(Util.FromBase64(privateKeyString));

        /* read MAC */
        line = reader.ReadLine();
        m = MatchOrThrow(line, "^("+privateMACKey+"|"+privateHashKey+"): ?([0-9a-fA-F]+)$");
        if (m.Groups[1].Value != privateMACKey) {
          fileData.isHMAC = false;
          if (m.Groups[1].Value != privateHashKey || fileData.ppkFileVersion != Version.V1) {
            throw new PpkFormatterException(PpkFormatterException.PpkErrorType.FileFormat,
                                            privateMACKey + " expected");
          }
        } else {
          fileData.isHMAC = true;
        }
        string privateMACString = m.Groups[2].Value;
        fileData.privateMAC = Util.FromHex(privateMACString);


        /* get passphrase and decrypt private key if required */

        Aes cipher;
        HashAlgorithm mac;
        fileData.passphrase = GetPassphraseCallbackMethod.Invoke(fileData.comment);
        CreateKeyMaterial(fileData, out cipher, out mac);

        DecryptPrivateKey(ref fileData, cipher);
        VerifyIntegrity(fileData, mac);

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

    private static void DecryptPrivateKey(ref FileData fileData, SymmetricAlgorithm cipher)
    {
      if (cipher == null) return;
      ICryptoTransform decryptor = cipher.CreateDecryptor();
      fileData.privateKeyBlob.Data = Util.GenericTransform(decryptor, fileData.privateKeyBlob.Data);
      decryptor.Dispose();
      cipher.Clear();
    }

    private static void CreateKeyMaterial(FileData fileData, out Aes cipher, out HashAlgorithm mac)
    {
      switch (fileData.ppkFileVersion) {
        case Version.V1:
        case Version.V2:
          /* begin symmetric key+iv */
          SHA1 sha = SHA1.Create();
          cipher = null;
          if (fileData.passphrase != null) {
            using (var passphrase = fileData.passphrase.ToAnsiArray()) {
              byte[] hashInput = new byte[4 + passphrase.Data.Length];
              byte[] hash0 = null;
              byte[] hash1 = null;
              try {
                hashInput[3] = 0;
                Array.Copy(passphrase.Data, 0, hashInput, 4, passphrase.Data.Length);
                hash0 = sha.ComputeHash(hashInput);

                hashInput[3] = 1;
                hash1 = sha.ComputeHash(hashInput);

                cipher = Aes.Create();
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.None;
                cipher.Key = hash0.Concat(hash1).Take(cipherLength).ToArray();
                cipher.IV = new byte[ivLength];
              } finally {
                if (hash0 != null) Array.Clear(hash0, 0, hash0.Length);
                if (hash1 != null) Array.Clear(hash1, 0, hash0.Length);
                Array.Clear(hashInput, 0, hashInput.Length);
              }
            }
          }
          /* end symmetric key+iv */

          /* begin mac key */

          if (fileData.isHMAC) {
            mac = new HMACSHA1();
            if (fileData.passphrase != null) {
              using (var passphrase = fileData.passphrase.ToAnsiArray()) {
                byte[] tmp = Encoding.UTF8.GetBytes(cMACKeySalt).Concat(passphrase.Data).ToArray();
                ((HMAC) mac).Key = sha.ComputeHash(tmp);
                Array.Clear(tmp, 0, tmp.Length);
              }
            } else {
              ((HMAC) mac).Key = sha.ComputeHash(Encoding.UTF8.GetBytes(cMACKeySalt));
            }
          } else {
            mac = SHA1.Create();
          }

          /* end mac key */

          sha.Clear();
          break;
        case Version.V3:
          if (fileData.passphrase == null) {
            cipher = null;
            mac = new HMACSHA256(Array.Empty<byte>());
            break;
          }
          using (var passphrase = fileData.passphrase.ToAnsiArray()) {
            Argon2 hasher;
            switch (fileData.kdfAlgorithm) {
              case KeyDerivation.Argon2i:
                hasher = new Argon2i(passphrase.Data);
                break;
              case KeyDerivation.Argon2d:
                hasher = new Argon2d(passphrase.Data);
                break;
              case KeyDerivation.Argon2id:
                hasher = new Argon2id(passphrase.Data);
                break;
              default:
                throw new ArgumentOutOfRangeException();
            }
            hasher.MemorySize = (int) fileData.kdfParameters[argonMemoryKey];
            hasher.Iterations = (int) fileData.kdfParameters[argonPassesKey];
            hasher.DegreeOfParallelism = (int) fileData.kdfParameters[argonParallelismKey];
            hasher.Salt = (byte[]) fileData.kdfParameters[argonSaltKey];

            // These values are copied by Aes and HMACSHA256 which
            // means they aren't explicitly zeroed unless we do it.
            // and then cipher.Clear() and mac.Clear() need to be
            // called once they're no longer in use.
            byte[] kdf = hasher.GetBytes(cipherLength + ivLength + macLength);
            byte[] key = kdf.Skip(0).Take(cipherLength).ToArray();
            byte[] iv = kdf.Skip(cipherLength).Take(ivLength).ToArray();
            byte[] mackey = kdf.Skip(cipherLength+ivLength).Take(macLength).ToArray();

            cipher = Aes.Create();
            cipher.Mode = CipherMode.CBC;
            cipher.Padding = PaddingMode.None;
            cipher.Key = key;
            cipher.IV = iv;

            mac = new HMACSHA256(mackey);

            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
            Array.Clear(mackey, 0, mackey.Length);
            Array.Clear(kdf, 0, kdf.Length);
          }

          break;
        default:
          throw new ArgumentOutOfRangeException();
      }
    }

    private static void VerifyIntegrity(FileData fileData, HashAlgorithm mac)
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

      byte[] computedHash = mac.ComputeHash(builder.GetBlob());

      builder.Clear();

      try {
        if (fileData.privateMAC.SequenceEqual(computedHash)) return;
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
      } finally {
        Array.Clear(computedHash, 0, computedHash.Length);
      }
    }

    private static Match MatchOrThrow(string line, string regex)
    {
      Match m = Regex.Match(line, regex);
      if (!m.Success)
        throw new PpkFormatterException(
          PpkFormatterException.PpkErrorType.FileFormat, regex + " expected");
      return m;
    }

    private static AsymmetricCipherKeyPair CreateCipherKeyPair(
      PublicKeyAlgorithm algorithm,
      byte[] publicKeyBlob, byte[] privateKeyBlob)
    {
      var parser = new BlobParser(publicKeyBlob);
      OpensshCertificate cert;
      var publicKey = parser.ReadSsh2PublicKeyData(out cert);
      parser = new BlobParser(privateKeyBlob);

      switch (algorithm) {
        case PublicKeyAlgorithm.SSH_RSA:
          var rsaPublicKeyParams = (RsaKeyParameters)publicKey;

          var d = new BigInteger(1, parser.ReadBlob());
          var p = new BigInteger(1, parser.ReadBlob());
          var q = new BigInteger(1, parser.ReadBlob());
          var inverseQ = new BigInteger(1, parser.ReadBlob());

          /* compute missing parameters */
          var dp = d.Remainder(p.Subtract(BigInteger.One));
          var dq = d.Remainder(q.Subtract(BigInteger.One));

          RsaPrivateCrtKeyParameters rsaPrivateKeyParams =
            new RsaPrivateCrtKeyParameters(rsaPublicKeyParams.Modulus,
              rsaPublicKeyParams.Exponent, d, p, q, dp, dq, inverseQ);

          return new AsymmetricCipherKeyPair(rsaPublicKeyParams,
            rsaPrivateKeyParams);

        case PublicKeyAlgorithm.SSH_DSS:
          var dsaPublicKeyParams = (DsaPublicKeyParameters)publicKey;

          var x = new BigInteger(1, parser.ReadBlob());
          DsaPrivateKeyParameters dsaPrivateKeyParams =
            new DsaPrivateKeyParameters(x, dsaPublicKeyParams.Parameters);

          return new AsymmetricCipherKeyPair(dsaPublicKeyParams,
            dsaPrivateKeyParams);
        case PublicKeyAlgorithm.ED25519:
          var ed25596PublicKey = (Ed25519PublicKeyParameter)publicKey;

          byte[] privBlob = parser.ReadBlob();
          byte[] privSig = new byte[64];
          // OpenSSH's "private key" is actually the private key with the public key tacked on ...
          Array.Copy(privBlob, 0, privSig, 0, 32);
          Array.Copy(ed25596PublicKey.Key, 0, privSig, 32, 32);
          var ed25596PrivateKey = new Ed25519PrivateKeyParameter(privSig);

          return new AsymmetricCipherKeyPair(ed25596PublicKey, ed25596PrivateKey);
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP256:
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP384:
        case PublicKeyAlgorithm.ECDSA_SHA2_NISTP521:
          var ecPublicKeyParams = (ECPublicKeyParameters)publicKey;

          var ecdsaPrivate = new BigInteger(1, parser.ReadBlob());
          ECPrivateKeyParameters ecPrivateKeyParams =
            new ECPrivateKeyParameters(ecdsaPrivate, ecPublicKeyParams.Parameters);

          return new AsymmetricCipherKeyPair(ecPublicKeyParams, ecPrivateKeyParams);
        default:
          // unsupported encryption algorithm
          throw new PpkFormatterException(PpkFormatterException.PpkErrorType.PublicKeyEncryption);
      }
    }

    # endregion -- Private Methods --

  }

  static class PpkFormatterExt
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

    public static bool TryParsePublicKeyAlgorithm(this string text, ref PublicKeyAlgorithm algo)
    {
      switch (text) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY:
          algo = PublicKeyAlgorithm.SSH_RSA;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY:
          algo = PublicKeyAlgorithm.SSH_DSS;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP256_KEY:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP256;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP384_KEY:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP384;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ECDSA_SHA2_NISTP521_KEY:
          algo = PublicKeyAlgorithm.ECDSA_SHA2_NISTP521;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_ED25519:
          algo = PublicKeyAlgorithm.ED25519;
          return true;
        default:
          return false;
      }
    }
  }
}

