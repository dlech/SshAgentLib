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

      PasswordFinder pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
      StreamWriter streamWriter = new StreamWriter(aStream);
      PemWriter writer = new PemWriter(streamWriter);
      char[] passphrase = pwFinder.GetPassword();
      if (passphrase == null) {
        writer.WriteObject(aObject);
      } else {
        GCHandle ppHandle = GCHandle.Alloc(passphrase, GCHandleType.Pinned);
        writer.WriteObject(aObject, null, passphrase, null);
        Array.Clear(passphrase, 0, passphrase.Length);
        ppHandle.Free();
      }
    }

    public override object Deserialize(Stream aStream)
    {
      /* check for required parameters */
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }
      PasswordFinder pwFinder = new PasswordFinder(GetPassphraseCallbackMethod);
      StreamReader streamReader = new StreamReader(aStream);
        PemReader reader = new PemReader(streamReader, pwFinder);
        object data = reader.ReadObject();
        if (data is AsymmetricCipherKeyPair) {
          return new SshKey(SshVersion.SSH2, (AsymmetricCipherKeyPair)data);
        } else {
          throw new Exception("bad data");
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
        if (mCallback == null) {
          return null;
        }
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
