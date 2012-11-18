using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Collections.ObjectModel;
using System.Collections;
using System.Security.Cryptography;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace dlech.PageantSharp
{
  /// <summary>
  /// Used to read PuTTY Private Key (.ppk) files
  /// </summary>
  public static class PpkFile
  {

    #region -- Constants --

    private const string cPrivateKeyDecryptSalt1 = "\0\0\0\0";
    private const string cPrivateKeyDecryptSalt2 = "\0\0\0\x1";
    private const string cMACKeySalt = "putty-private-key-file-mac-key";

    /// <summary>
    /// The delimiter used by the file
    /// </summary>
    private const char cDelimeter = ':';

    /// <summary>
    /// contains fields with valid file version strings
    /// </summary>
    private enum Version
    {
      V1,
      V2
    }

    private static string GetName(this Version aVersion)
    {
      switch (aVersion) {
        case Version.V1:
          return "1";
        case Version.V2:
          return "2";
        default:
          Debug.Fail("Unknown version");
          throw new Exception("Unknown version");
      }
    }

    private static bool TryParseVersion(this string aString, ref Version aVersion)
    {
      switch (aString) {
        case "1":
          aVersion = Version.V1;
          return true;
        case "2":
          aVersion = Version.V2;
          return true;
        default:
          return false;
      }
    }

    private static bool TryParsePublicKeyAlgorithm(this string aString,
      ref PublicKeyAlgorithm aAlgorithm)
    {      
      switch (aString) {
        case PublicKeyAlgorithmExt.ALGORITHM_RSA_KEY:
          aAlgorithm = PublicKeyAlgorithm.SSH_RSA;
          return true;
        case PublicKeyAlgorithmExt.ALGORITHM_DSA_KEY:
          aAlgorithm = PublicKeyAlgorithm.SSH_DSS;
          return true;
        default:
          return false;
      }
    }
    
    private const string ALGORITHM_NONE = "none";
    private const string ALGORITHM_AES256_CBC = "aes256-cbc";

    /// <summary>
    /// Valid private key encryption algorithms
    /// </summary>
    private enum PrivateKeyAlgorithm
    {
      None,
      AES256_CBC
    }

    private static string GetIdentifierString(this PrivateKeyAlgorithm aAlgorithm) {
      switch (aAlgorithm) {
        case PrivateKeyAlgorithm.None:
          return ALGORITHM_NONE;
        case PrivateKeyAlgorithm.AES256_CBC:
          return ALGORITHM_AES256_CBC;
        default:
          Debug.Fail("Unknown algorithm");
          throw new Exception("Unknown algorithm");
      }
    }

    private static bool TryParsePrivateKeyAlgorithm(this string aString,
      ref PrivateKeyAlgorithm aAlgorithm)
    {
      switch (aString) {
        case ALGORITHM_NONE:
          aAlgorithm = PrivateKeyAlgorithm.None;
          return true;
        case ALGORITHM_AES256_CBC:
          aAlgorithm = PrivateKeyAlgorithm.AES256_CBC;
          return true;
        default:
          return false;
      }
    }
        
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

    #endregion -- Constants --


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
      public PinnedByteArray privateKeyBlob;

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
    /// Gets passphrase. This method is only called if the file requires a passphrase.
    /// </summary>
    /// <returns></returns>
    public delegate SecureString GetPassphraseCallback();

    /// <summary>
    /// Implementation of this function shoud warn the user that they are using
    /// an old file format that has know security issues.
    /// </summary>
    public delegate void WarnOldFileFormatCallback();

    #endregion -- Delegates --


    #region -- Constructors --



    #endregion -- Constructors --


    #region -- Public Methods --


    /// <summary>
    /// Reads the specified file, parsed data and creates new PpkKey object
    /// from file data
    /// </summary>
    /// <param name="fileName">The name of the file to open</param>
    /// <param name="getPassphrase">Callback method for getting passphrase
    /// if required. Can be null if no passphrase.</param>
    /// <param name="warnOldFileFormat">Callback method that warns user that
    /// they are using an old file format with known security problems.</param>
    /// <exception cref="dlech.PageantSharp.PpkFileException">there was a problem reading the file</exception>
    /// <exception cref="System.ArgumentNullException">fileName and warnOldFileFormat cannot be null</exception>
    /// <exception cref="System.ArgumentException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
    /// <exception cref="System.IO.PathTooLongException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
    /// <exception cref="System.IO.DirectoryNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
    /// <exception cref="System.UnauthorizedAccessException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
    /// <exception cref="System.IO.FileNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
    /// <exception cref="System.NotSupportedException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
    public static SshKey ReadFile(string fileName,
                                  GetPassphraseCallback getPassphrase,
                                  WarnOldFileFormatCallback warnOldFileFormat)
    {
      FileStream stream;
      byte[] buffer;

      using (stream = File.OpenRead(fileName)) {
        buffer = new byte[stream.Length];
        stream.Read(buffer, 0, buffer.Length);
      }
      return ParseData(buffer, getPassphrase, warnOldFileFormat);
    }

    /// <summary>
    /// Parses the data from a PuTTY Private Key (.ppk) file.
    /// </summary>
    /// <param name="data">The data to parse.</param>
    /// <param name="getPassphrase">Callback method for getting passphrase
    /// if required. Can be null if no passphrase.</param>
    /// <param name="warnOldFileFormat">Callback method that warns user that
    /// they are using an old file format with known security problems.</param>
    /// <exception cref="dlech.PageantSharp.PpkFileException">
    /// there was a problem parsing the file data
    /// </exception>
    /// <exception cref="System.ArgumentNullException">
    /// data and warnOldFileFormat cannot be null
    /// </exception>
    public static SshKey ParseData(byte[] data,
                                   GetPassphraseCallback getPassphrase,
                                   WarnOldFileFormatCallback warnOldFileFormat)
    {
      FileData fileData = new FileData();

      /* check for required parameters */
      if (data == null) {
        throw new ArgumentNullException("data");
      }
      if (warnOldFileFormat == null) {
        throw new ArgumentNullException("warnOldFileFormat");
      }

      string line;
      string[] pair = new string[2];
      int lineCount, i;

      Stream stream = new MemoryStream(data);
      StreamReader reader = new StreamReader(stream);
      char[] delimArray = { cDelimeter };

      try {
        /* read file version */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (!pair[0].StartsWith(puttyUserKeyFileKey)) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     puttyUserKeyFileKey + " expected");
        }        
        string ppkFileVersion = pair[0].Remove(0, puttyUserKeyFileKey.Length);
        if (!ppkFileVersion.TryParseVersion(ref fileData.ppkFileVersion)) {
          throw new PpkFileException(PpkFileException.ErrorType.FileVersion);
        }
        if (fileData.ppkFileVersion == Version.V1) {
          warnOldFileFormat();
        }

        /* read public key encryption algorithm type */
        string algorithm = pair[1].Trim();
        if (!algorithm.TryParsePublicKeyAlgorithm(ref fileData.publicKeyAlgorithm)) {
          throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
        }

        /* read private key encryption algorithm type */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != privateKeyEncryptionKey) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     privateKeyEncryptionKey + " expected");
        }
        algorithm = pair[1].Trim();
        if (!algorithm.TryParsePrivateKeyAlgorithm(ref fileData.privateKeyAlgorithm)) {
          throw new PpkFileException(PpkFileException.ErrorType.PrivateKeyEncryption);
        }

        /* read comment */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != commentKey) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     commentKey + " expected");
        }
        fileData.comment = pair[1].Trim();

        /* read public key */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != publicKeyLinesKey) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     publicKeyLinesKey + " expected");
        }
        if (!int.TryParse(pair[1], out lineCount)) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     "integer expected");
        }
        string publicKeyString = string.Empty;
        for (i = 0; i < lineCount; i++) {
          publicKeyString += reader.ReadLine();
        }
        fileData.publicKeyBlob = PSUtil.FromBase64(publicKeyString);

        /* read private key */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != privateKeyLinesKey) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     privateKeyLinesKey + " expected");
        }
        if (!int.TryParse(pair[1], out lineCount)) {
          throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                     "integer expected");
        }
        string privateKeyString = string.Empty;
        for (i = 0; i < lineCount; i++) {
          privateKeyString += reader.ReadLine();
        }
        fileData.privateKeyBlob = new PinnedByteArray(PSUtil.FromBase64(privateKeyString));

        /* read MAC */
        line = reader.ReadLine();
        pair = line.Split(delimArray, 2);
        if (pair[0] != privateMACKey) {
          fileData.isHMAC = false;
          if (pair[0] != privateHashKey || fileData.ppkFileVersion != Version.V1) {
            throw new PpkFileException(PpkFileException.ErrorType.FileFormat,
                                       privateMACKey + " expected");
          }
        } else {
          fileData.isHMAC = true;
        }
        string privateMACString = pair[1].Trim();
        fileData.privateMAC = PSUtil.FromHex(privateMACString);


        /* get passphrase and decrypt private key if required */
        if (fileData.privateKeyAlgorithm != PrivateKeyAlgorithm.None) {
          if (getPassphrase == null) {
            throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
          }
          fileData.passphrase = getPassphrase();
          DecryptPrivateKey(ref fileData);
        }

        VerifyIntegrity(fileData);

        AsymmetricCipherKeyPair cipherKeyPair =
          CreateCipherKeyPair(fileData.publicKeyAlgorithm,
          fileData.publicKeyBlob, fileData.privateKeyBlob.Data);
        SshKey key = new SshKey(SshVersion.SSH2, cipherKeyPair, fileData.comment);
        return key;

      } catch (PpkFileException) {
        throw;
      } catch (Exception ex) {
        throw new PpkFileException(
            PpkFileException.ErrorType.FileFormat,
            "See inner exception.", ex);
      } finally {
        Array.Clear(data, 0, data.Length);
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
        stream.Close();
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

          using (PinnedByteArray hashData =
                 new PinnedByteArray(cPrivateKeyDecryptSalt1.Length +
                                     fileData.passphrase.Length)) {
            Array.Copy(Encoding.UTF8.GetBytes(cPrivateKeyDecryptSalt1),
                       hashData.Data, cPrivateKeyDecryptSalt1.Length);
            IntPtr passphrasePtr =
              Marshal.SecureStringToGlobalAllocUnicode(fileData.passphrase);
            for (int i = 0; i < fileData.passphrase.Length; i++) {
              int unicodeChar = Marshal.ReadInt16(passphrasePtr + i * 2);
              byte ansiChar = PSUtil.UnicodeToAnsi(unicodeChar);
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
          PSUtil.ClearByteList(key);
          aes.IV = new byte[aes.IV.Length];
          ICryptoTransform decryptor = aes.CreateDecryptor();
          fileData.privateKeyBlob.Data =
            PSUtil.GenericTransform(decryptor, fileData.privateKeyBlob.Data);
          decryptor.Dispose();
          aes.Clear();
          break;

        default:
          throw new PpkFileException(PpkFileException.ErrorType.PrivateKeyEncryption);
      }
    }

    private static void VerifyIntegrity(FileData fileData)
    {

      BlobBuilder builder = new BlobBuilder();
      if (fileData.ppkFileVersion != Version.V1) {
        builder.AddStringBlob(fileData.publicKeyAlgorithm.GetIdentifierString());
        builder.AddStringBlob(fileData.privateKeyAlgorithm.GetIdentifierString());
        builder.AddStringBlob(fileData.comment);
        builder.AddBlob(fileData.publicKeyBlob);
        builder.AddInt(fileData.privateKeyBlob.Data.Length);
      }
      builder.AddBytes(fileData.privateKeyBlob.Data);

      byte[] computedHash;
      SHA1 sha = SHA1.Create();
      if (fileData.isHMAC) {
        HMAC hmac = HMACSHA1.Create();
        if (fileData.passphrase != null) {
          using (PinnedByteArray hashData =
                 new PinnedByteArray(cMACKeySalt.Length + fileData.passphrase.Length)) {
            Array.Copy(Encoding.UTF8.GetBytes(cMACKeySalt),
                       hashData.Data, cMACKeySalt.Length);
            IntPtr passphrasePtr =
              Marshal.SecureStringToGlobalAllocUnicode(fileData.passphrase);
            for (int i = 0; i < fileData.passphrase.Length; i++) {
              int unicodeChar = Marshal.ReadInt16(passphrasePtr + i * 2);
              byte ansiChar = PSUtil.UnicodeToAnsi(unicodeChar);
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
            throw new PpkFileException(PpkFileException.ErrorType.FileCorrupt);
          } else {
            // if the bytes are not zeros, we assume that the data was not
            // properly decrypted because the passphrase was incorrect.
            throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
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
      BigInteger exponent, modulus, d, p, q, inverseQ, dp, dq; // rsa params
      BigInteger /* p, q, */ g, y, x; // dsa params

      PpkKeyBlobParser parser = new PpkKeyBlobParser(aPublicKeyBlob);
      string algorithm = Encoding.UTF8.GetString(parser.CurrentAsPinnedByteArray.Data);
      parser.CurrentAsPinnedByteArray.Dispose();
      parser.MoveNext();
      if (algorithm != aAlgorithm.GetIdentifierString()) {
        throw new InvalidOperationException("public key is not " + aAlgorithm.GetIdentifierString());
      }

      switch (aAlgorithm) {
        case PublicKeyAlgorithm.SSH_RSA:       

          /* read parameters that were stored in file */

          exponent = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          modulus = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          //parser.MoveNext();

          parser = new PpkKeyBlobParser(aPrivateKeyBlob);

          d = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          p = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          q = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          inverseQ = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          //parser.MoveNext();

          /* compute missing parameters */
          dp = d.Remainder(p.Subtract(BigInteger.One));
          dq = d.Remainder(q.Subtract(BigInteger.One));

          RsaKeyParameters rsaPublicKeyParams = new RsaKeyParameters(false, modulus, exponent);
          RsaPrivateCrtKeyParameters rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
              modulus, exponent, d, p, q, dp, dq, inverseQ
          );

          parser.Dispose();

          return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);

        case PublicKeyAlgorithm.SSH_DSS:          

          /* read parameters that were stored in file */

          p = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          q = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          g = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          parser.MoveNext();
          y = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          //parser.MoveNext();

          parser = new PpkKeyBlobParser(aPrivateKeyBlob);

          PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
          x = new BigInteger(1, parser.CurrentAsPinnedByteArray.Data);
          //parser.MoveNext();

          DsaParameters commonParams = new DsaParameters(p, q, g);
          DsaPublicKeyParameters dsaPublicKeyParams = new DsaPublicKeyParameters(
              y, commonParams
          );
          DsaPrivateKeyParameters dsaPrivateKeyParams = new DsaPrivateKeyParameters(
              x, commonParams
          );

          parser.Dispose();

          return new AsymmetricCipherKeyPair(dsaPublicKeyParams, dsaPrivateKeyParams);
        default:
          // unsupported encryption algorithm
          throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
      }
    }

    # endregion -- Private Methods --

  }
}

