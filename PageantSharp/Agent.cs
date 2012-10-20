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
    GetSSH2KeyListCallback mGetSSH2KeyListCallback;
    GetSSH2KeyCallback mGetSSH2KeyCallback;
    AddSSH2KeyCallback mAddSSH2KeyCallback;
    #endregion


    /// <summary>
    /// Implementer should create list of PpkKeys to be iterated by WinPageant.
    /// </summary>
    /// <returns>List of PpkKey objects. Keys will be disposed by callback, 
    /// so a new list should be created on each call</returns>
    public delegate IEnumerable<PpkKey> GetSSH2KeyListCallback();

    /// <summary>
    /// Implementer should return the specific key that matches the fingerprint.
    /// </summary>
    /// <param name="fingerprint">PpkKey object that matches fingerprint or null.
    /// Keys will be disposed by callback, so a new object should be created on each call</param>
    /// <returns></returns>
    public delegate PpkKey GetSSH2KeyCallback(byte[] fingerprint);

    /// <summary>
    /// Implementer should ...
    /// </summary>
    /// <returns></returns>
    public delegate bool AddSSH2KeyCallback(PpkKey key);

    public Agent(GetSSH2KeyListCallback aGetSSH2KeyListCallback,
      GetSSH2KeyCallback aGetSSH2KeyCallback,
      AddSSH2KeyCallback aAddSSH2KeyCallback)
    {
      mGetSSH2KeyListCallback = aGetSSH2KeyListCallback;
      mGetSSH2KeyCallback = aGetSSH2KeyCallback;
      mAddSSH2KeyCallback = aAddSSH2KeyCallback;
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
          if (mGetSSH2KeyListCallback == null) {
            Debug.Fail("no callback in SSH2_AGENTC_REQUEST_IDENTITIES");
            goto default; // can't reply without callback
          }
          BlobBuilder builder = new BlobBuilder();
          try {
            int keyCount = 0;

            foreach (PpkKey key in mGetSSH2KeyListCallback()) {
              keyCount++;
              builder.AddBlob(OpenSsh.GetSSH2PublicKeyBlob(key.CipherKeyPair));
              builder.AddString(key.Comment);
              key.Dispose();
            }
            if (aMessageStream.Length < 9 + builder.Length) {
              Debug.Fail("Not enough room in buffer in SSH2_AGENTC_REQUEST_IDENTITIES");
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
          if (mGetSSH2KeyCallback == null) {
            Debug.Fail("No callback for SSH2_AGENTC_SIGN_REQUEST");
            goto default; // can't reply without callback
          }
          try {
            byte[] keyBlob = parser.Read();
            byte[] reqData = parser.Read();

            /* get matching key from callback */
            MD5 md5 = MD5.Create();
            byte[] fingerprint = md5.ComputeHash(keyBlob);
            md5.Clear();
            using (PpkKey key = mGetSSH2KeyCallback(fingerprint)) {
              if (key == null) {
                Debug.Fail("callback did not return key in SSH2_AGENTC_SIGN_REQUEST");
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
                Debug.Fail("unsupported algorithm in SSH2_AGENTC_SIGN_REQUEST");
                goto default;
              }
              signer.Init(true, key.CipherKeyPair.Private);
              signer.BlockUpdate(reqData, 0, reqData.Length);
              byte[] signature = signer.GenerateSignature();

              BlobBuilder sigBlobBuilder = new BlobBuilder();
              sigBlobBuilder.AddString(algName);
              sigBlobBuilder.AddBlob(signature);
              signature = sigBlobBuilder.GetBlob();
              sigBlobBuilder.Clear();

              if (aMessageStream.Length < 9 + signature.Length) {
                Debug.Fail("Not enough room in buffer in SSH2_AGENTC_SIGN_REQUEST");
                goto default;
              }

              /* write response to filemap */

              aMessageStream.Position = 0;
              aMessageStream.Write(PSUtil.IntToBytes(5 + signature.Length), 0, 4);
              aMessageStream.WriteByte((byte)OpenSsh.Message.SSH2_AGENT_SIGN_RESPONSE);
              aMessageStream.Write(PSUtil.IntToBytes(signature.Length), 0, 4);
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

          if (mAddSSH2KeyCallback == null) {
            Debug.Fail("No callback for SSH2_AGENTC_ADD_IDENTITY");
            goto default; // can't reply without callback
          }
          try {
            PpkKey key = new PpkKey();
            key.CipherKeyPair = OpenSsh.CreateCipherKeyPair(aMessageStream);
            key.Comment = Encoding.UTF8.GetString(parser.Read());

            /* do callback */
            if (mAddSSH2KeyCallback(key)) {
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

          // TODO implement SSH2_AGENTC_REMOVE_IDENTITY

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

          // TODO implement SSH2_AGENTC_REMOVE_ALL_IDENTITIES

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

