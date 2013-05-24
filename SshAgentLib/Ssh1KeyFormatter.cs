using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security;
using System.Runtime.InteropServices;
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
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }

      if (aObject == null) {
        throw new ArgumentNullException("aObject");
      }

      PasswordFinder pwFinder = null;
      if (GetPassphraseCallbackMethod != null) {
        pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
      }
      PinnedArray<char> passphrase = null;
      if (pwFinder != null) {
        passphrase = new PinnedArray<char>(0);
        passphrase.Data = pwFinder.GetPassword();
      }

      byte cipherType;
      if (passphrase == null || passphrase.Data.Length == 0) {
        cipherType = SSH_CIPHER_NONE;
      } else {
        cipherType = SSH_CIPHER_3DES;
      }

      BlobBuilder builder = new BlobBuilder();

      ISshKey sshKey = aObject as ISshKey;
      RsaKeyParameters publicKeyParams = sshKey.GetPublicKeyParameters()
        as RsaKeyParameters;
      RsaPrivateCrtKeyParameters privateKeyParams = sshKey.GetPrivateKeyParameters()
        as RsaPrivateCrtKeyParameters;

      /* writing info headers */
      builder.AddBytes(Encoding.ASCII.GetBytes(FILE_HEADER_LINE + "\n"));
      builder.AddByte(0);          //end of string
      builder.AddByte(cipherType); //cipher
      builder.AddInt(0);           //reserved

      /* writing public key */
      builder.AddInt(sshKey.Size);
      builder.AddSsh1BigIntBlob(publicKeyParams.Modulus);
      builder.AddSsh1BigIntBlob(publicKeyParams.Exponent);
      builder.AddStringBlob(sshKey.Comment);

      /* writing private key */
      BlobBuilder privateKeyBuilder = new BlobBuilder();

      /* adding some control values */
      Random random = new Random();
      byte[] resultCheck = new byte[2];
      random.NextBytes(resultCheck);

      privateKeyBuilder.AddByte(resultCheck[0]);
      privateKeyBuilder.AddByte(resultCheck[1]);
      privateKeyBuilder.AddByte(resultCheck[0]);
      privateKeyBuilder.AddByte(resultCheck[1]);
      privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.Exponent);
      privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.DQ);
      privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.P);
      privateKeyBuilder.AddSsh1BigIntBlob(privateKeyParams.Q);

      if (cipherType == SSH_CIPHER_NONE) {
        /* plain-text */
        builder.AddBytes(privateKeyBuilder.GetBlobAsPinnedByteArray().Data);
      } else {
        byte[] keydata;
        using (MD5 md5 = MD5.Create()) {
          keydata = md5.ComputeHash(Encoding.ASCII.GetBytes(passphrase.Data));
        }

        /* encryption */
        DesSsh1Engine desEngine = new DesSsh1Engine();
        desEngine.Init(true, new KeyParameter(keydata));

        BufferedBlockCipher bufferedBlockCipher = new BufferedBlockCipher(desEngine);
        byte[] ouputBuffer = bufferedBlockCipher.ProcessBytes(
          privateKeyBuilder.GetBlobAsPinnedByteArray().Data);

        builder.AddBytes(ouputBuffer);

        passphrase.Dispose();
      }

      /* writing result to file */
      var builderOutput = builder.GetBlobAsPinnedByteArray();
      aStream.Write(builderOutput.Data, 0, builderOutput.Data.Length);
      aStream.Close();
    }

    public override object Deserialize(Stream aStream)
    {
      /* check for required parameters */
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }

      /* reading unencrypted part */
      BlobParser parser = new BlobParser(aStream);

      parser.ReadBytes((uint)FILE_HEADER_LINE.Length + 2);  //Skipping header line

      byte cipherType = parser.ReadByte();
      if (cipherType != SSH_CIPHER_3DES && cipherType != SSH_CIPHER_NONE) {
        //TripleDes is the only encryption supported
        throw new KeyFormatterException("Unsupported cypherType: " + cipherType);
      }

      parser.ReadInt(); //reserved

      /* reading public key */
      AsymmetricKeyParameter aPublicKeyParameter =
         parser.ReadSsh1PublicKeyData(false);
      String keyComment = parser.ReadString();

      /* reading private key */
      byte[] inputBuffer = new byte[aStream.Length];
      aStream.Read(inputBuffer, 0, inputBuffer.Length);
      byte[] ouputBuffer;

      try {
        if (cipherType == 3) {
          /* private key is 3DES encrypted */
          PasswordFinder pwFinder = null;
          if (GetPassphraseCallbackMethod != null) {
            pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
          }

          byte[] keydata;
          try {
            using (MD5 md5 = MD5.Create()) {
              char[] md5Buffer = pwFinder.GetPassword();
              keydata = md5.ComputeHash(Encoding.ASCII.GetBytes(md5Buffer));
            }
          } catch (PasswordException ex) {
            if (GetPassphraseCallbackMethod == null) {
              throw new CallbackNullException();
            }
            throw new KeyFormatterException("see inner exception", ex);
          }

          /* decryption */
          DesSsh1Engine desEngine = new DesSsh1Engine();
          desEngine.Init(false, new KeyParameter(keydata));

          BufferedBlockCipher bufferedBlockCipher = new BufferedBlockCipher(desEngine);
          ouputBuffer = bufferedBlockCipher.ProcessBytes(inputBuffer);

        } else {
          /* private key is stored in plain text */
          ouputBuffer = inputBuffer;
        }

        var privateKeyParser = new BlobParser(ouputBuffer);

        /* checking result of decryption */
        byte[] resultCheck = privateKeyParser.ReadBytes(4);
        if (resultCheck[0] != resultCheck[2] || resultCheck[1] != resultCheck[3]) {
          throw new KeyFormatterException("bad passphrase");
        }

        /* reading private key */
        var keyPair = privateKeyParser.ReadSsh1KeyData(aPublicKeyParameter);
        SshKey key = new SshKey(SshVersion.SSH1, keyPair);
        key.Comment = keyComment;
        return key;
      } catch (KeyFormatterException) {
        throw;
      } catch (Exception ex) {
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
        SecureString passphrase = mCallback.Invoke();
        char[] passwordChars = new char[passphrase.Length];
        IntPtr passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(passphrase);
        for (int i = 0; i < passphrase.Length; i++) {
          passwordChars[i] = (char)Marshal.ReadInt16(passphrasePtr, i * 2);
        }
        Marshal.ZeroFreeGlobalAllocUnicode(passphrasePtr);
        return passwordChars;
      }
    }

  }
}
