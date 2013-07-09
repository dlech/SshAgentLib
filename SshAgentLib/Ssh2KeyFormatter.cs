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
using System.Runtime.Serialization;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Formats SSH2 public keys in file format specified by RFC 4716
  /// </summary>
  public class Ssh2KeyFormatter : KeyFormatter
  {

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
      StreamWriter streamWriter = new StreamWriter(aStream);
      PemWriter writer = new PemWriter(streamWriter);
      PinnedArray<char> passphrase = null;
      if (pwFinder != null) {
        passphrase = new PinnedArray<char>(0);
        passphrase.Data = pwFinder.GetPassword();
      }
      if (passphrase == null) {
        writer.WriteObject(aObject);
      } else {
        writer.WriteObject(aObject, null, passphrase.Data, null);
        passphrase.Dispose();
      }
    }

    public override object Deserialize(Stream aStream)
    {
      /* check for required parameters */
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }
      PasswordFinder pwFinder = null;
      if (GetPassphraseCallbackMethod != null) {
        pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
      }
      try {
        StreamReader streamReader = new StreamReader(aStream);
        PemReader reader = new PemReader(streamReader, pwFinder);
        object data = reader.ReadObject();

        if (data is AsymmetricCipherKeyPair) {
          return new SshKey(SshVersion.SSH2, (AsymmetricCipherKeyPair)data);
        } else {
          throw new KeyFormatterException("bad data");
        }
      } catch (PasswordException ex) {
        if (GetPassphraseCallbackMethod == null) {
          throw new CallbackNullException();
        }
        throw new KeyFormatterException("see inner exception", ex);
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
        SecureString passphrase = mCallback.Invoke(null);
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
