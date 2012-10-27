using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;

namespace dlech.PageantSharp
{
  public abstract class Agent : IDisposable
  {
    #region Instance Variables
    private CallBacks mCallbacks;
    #endregion


    /// <summary>
    /// Implementer should return a list of public keys that will be 
    /// sent to a remote client
    /// </summary>
    /// <returns>List of PpkKey objects. Keys will be disposed by callback, 
    /// so a new list should be created on each call</returns>
    public delegate IEnumerable<PpkKey> GetSSH2KeyListCallback();

    /// <summary>
    /// Implementer should return the specific key that matches the fingerprint.
    /// </summary>
    /// <param name="fingerprint">MD5 fingerprint of key</param>
    /// <returns>PpkKey object that matches fingerprint or null.
    /// Keys will be disposed by callback, so a new object should be created on each call</returns>
    public delegate PpkKey GetSSH2KeyCallback(byte[] aFingerprint);

    /// <summary>
    /// Implementer should Add the specified key to its key store
    /// </summary>
    /// <returns></returns>
    public delegate bool AddSSH2KeyCallback(PpkKey key);

    /// <summary>
    /// Implementer should remove the specified key from its key store
    /// </summary>
    /// <param name="aFingerprint">MD5 fingerprint of key</param>
    /// <returns>true if key was removed</returns>
    public delegate bool RemoveSSH2KeyCallback(byte[] aFingerprint);

    /// <summary>
    /// Implementer should remove all keys from its key store
    /// </summary>
    /// <returns>true if all keys were removed</returns>
    public delegate bool RemoveAllSSH2KeysCallback();

    public struct CallBacks
    {
      public GetSSH2KeyListCallback getSSH2KeyList;
      public GetSSH2KeyCallback getSSH2Key;
      public AddSSH2KeyCallback addSSH2Key;
      public RemoveSSH2KeyCallback removeSSH2Key;
      public RemoveAllSSH2KeysCallback removeAllSSH2Keys;
    }

    public Agent(CallBacks aCallbacks)
    {
      mCallbacks = aCallbacks;
    }

    /// <summary>
    /// Answers the message.
    /// </summary>
    /// <param name='aMessageStream'>
    /// Message stream.
    /// </param>
    /// <remarks>code based on winpgnt.c from PuTTY source code</remarks>
    public void AnswerMessage(Stream aMessageStream)
    {
      BlobParser parser = new BlobParser(aMessageStream);
      OpenSsh.BlobHeader header = parser.ReadHeader();

      switch (header.Message) {
        case OpenSsh.Message.SSH1_AGENTC_REQUEST_RSA_IDENTITIES:
          /*
           * Reply with SSH1_AGENT_RSA_IDENTITIES_ANSWER.
           */

          // TODO implement SSH1_AGENT_RSA_IDENTITIES_ANSWER

          goto default; // failed
        case OpenSsh.Message.SSH2_AGENTC_REQUEST_IDENTITIES:
          /*
           * Reply with SSH2_AGENT_IDENTITIES_ANSWER.
           */
          if (mCallbacks.getSSH2KeyList == null) {
            goto default; // can't reply without callback
          }
          BlobBuilder builder = new BlobBuilder();
          try {
            int keyCount = 0;

            foreach (PpkKey key in mCallbacks.getSSH2KeyList()) {
              keyCount++;
              builder.AddBlob(OpenSsh.GetSSH2PublicKeyBlob(key.CipherKeyPair));
              builder.AddString(key.Comment);
              key.Dispose();
            }
            if (aMessageStream.Length < 9 + builder.Length) {
              goto default;
            }            
            aMessageStream.Position = 0;
            aMessageStream.Write(PSUtil.IntToBytes(5 + builder.Length), 0, 4);
            aMessageStream.WriteByte((byte)OpenSsh.Message.SSH2_AGENT_IDENTITIES_ANSWER);
            aMessageStream.Write(PSUtil.IntToBytes(keyCount), 0, 4);
            aMessageStream.Write(builder.GetBlob(), 0, builder.Length);
            break; // succeeded            
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          } finally {
            builder.Clear();
          }
          goto default; // failed
        case OpenSsh.Message.SSH1_AGENTC_RSA_CHALLENGE:
          /*
           * Reply with either SSH1_AGENT_RSA_RESPONSE or
           * SSH_AGENT_FAILURE, depending on whether we have that key
           * or not.
           */

          // TODO implement SSH1_AGENTC_RSA_CHALLENGE

          goto default; // failed
        case OpenSsh.Message.SSH2_AGENTC_SIGN_REQUEST:
          /*
           * Reply with either SSH2_AGENT_SIGN_RESPONSE or SSH_AGENT_FAILURE,
           * depending on whether we have that key or not.
           */
          if (mCallbacks.getSSH2Key == null) {
            goto default; // can't reply without callback
          }
          try {
            byte[] keyBlob = parser.Read();
            byte[] reqData = parser.Read();

            /* get matching key from callback */
            MD5 md5 = MD5.Create();
            byte[] fingerprint = md5.ComputeHash(keyBlob);
            md5.Clear();
            using (PpkKey key = mCallbacks.getSSH2Key(fingerprint)) {
              if (key == null) {
                goto default;
              }
              /* create signature */

              ISigner signer;
              string algName;
              if (key.CipherKeyPair.Public is RsaKeyParameters) {
                signer = SignerUtilities.GetSigner("SHA-1withRSA");
                algName = OpenSsh.PublicKeyAlgorithms.ssh_rsa;
              } else if (key.CipherKeyPair.Public is DsaPublicKeyParameters) {
                signer = SignerUtilities.GetSigner("SHA-1withDSA");
                algName = OpenSsh.PublicKeyAlgorithms.ssh_dss;
              } else {
                goto default;
              }
              signer.Init(true, key.CipherKeyPair.Private);
              signer.BlockUpdate(reqData, 0, reqData.Length);
              byte[] signature = signer.GenerateSignature();

              BlobBuilder sigBlobBuilder = new BlobBuilder();
              sigBlobBuilder.AddString(algName);
              sigBlobBuilder.AddBlob(signature);
              signature = sigBlobBuilder.GetBlob(OpenSsh.Message.SSH2_AGENT_SIGN_RESPONSE);
              sigBlobBuilder.Clear();

              if (aMessageStream.Length < 9 + signature.Length) {
                goto default;
              }

              /* write response to stream */

              aMessageStream.Position = 0;
              aMessageStream.Write(signature, 0, signature.Length);
              break; // succeeded
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failure
        case OpenSsh.Message.SSH1_AGENTC_ADD_RSA_IDENTITY:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          // TODO implement SSH1_AGENTC_ADD_RSA_IDENTITY

          goto default; // failed
        case OpenSsh.Message.SSH2_AGENTC_ADD_IDENTITY:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          if (mCallbacks.addSSH2Key == null) {
            goto default; // can't reply without callback
          }
          try {
            PpkKey key = new PpkKey();
            key.CipherKeyPair = OpenSsh.CreateCipherKeyPair(aMessageStream);
            key.Comment = Encoding.UTF8.GetString(parser.Read());

            /* do callback */
            if (mCallbacks.addSSH2Key(key)) {
              aMessageStream.Position = 0;
              aMessageStream.Write(PSUtil.IntToBytes(1), 0, 4);
              aMessageStream.WriteByte((byte)OpenSsh.Message.SSH_AGENT_SUCCESS);
              break; // success!
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed
        case OpenSsh.Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY:
          /*
           * Remove from the list and return SSH_AGENT_SUCCESS, or
           * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
           * start with.
           */

          // TODO implement SSH1_AGENTC_REMOVE_RSA_IDENTITY

          goto default; // failed
        case OpenSsh.Message.SSH2_AGENTC_REMOVE_IDENTITY:
          /*
           * Remove from the list and return SSH_AGENT_SUCCESS, or
           * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
           * start with.
           */

          if (mCallbacks.removeSSH2Key == null) {
            goto default;
          }
          
          byte[] rKeyBlob = parser.Read();          

          /* get matching key from callback */
          MD5 rMd5 = MD5.Create();
          byte[] rFingerprint = rMd5.ComputeHash(rKeyBlob);
          rMd5.Clear();

          if (mCallbacks.removeSSH2Key(rFingerprint)) {
            aMessageStream.Position = 0;
            aMessageStream.Write(PSUtil.IntToBytes(1), 0, 4);
            aMessageStream.WriteByte((byte)OpenSsh.Message.SSH_AGENT_SUCCESS);
            break; //success!
          }
          goto default; // failed
        case OpenSsh.Message.SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
          /*
           * Remove all SSH-1 keys. Always returns success.
           */

          // TODO implement SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES

          goto default; // failed
        case OpenSsh.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
          /*
           * Remove all SSH-2 keys. Always returns success.
           */

          if (mCallbacks.removeAllSSH2Keys == null) {
            goto default;
          }

          if (mCallbacks.removeAllSSH2Keys()) {
            aMessageStream.Position = 0;
            aMessageStream.Write(PSUtil.IntToBytes(1), 0, 4);
            aMessageStream.WriteByte((byte)OpenSsh.Message.SSH_AGENT_SUCCESS);
            break; //success!
          }

          goto default; // failed

        default:
          aMessageStream.Position = 0;
          aMessageStream.Write(PSUtil.IntToBytes(1), 0, 4);
          aMessageStream.WriteByte((byte)OpenSsh.Message.SSH_AGENT_FAILURE);
          break;
      }
    }

    public virtual void Dispose()
    {

    }
  }
}

