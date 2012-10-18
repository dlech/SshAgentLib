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
    /* Protocol message numbers - from PROTOCOL.agent in openssh source code */

    /* Requests from client to agent for protocol 1 key operations */
    private const int SSH1_AGENTC_REQUEST_RSA_IDENTITIES = 1;
    private const int SSH1_AGENTC_RSA_CHALLENGE = 3;
    private const int SSH1_AGENTC_ADD_RSA_IDENTITY = 7;
    private const int SSH1_AGENTC_REMOVE_RSA_IDENTITY = 8;
    private const int SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;
    private const int SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED = 24;

    /* Requests from client to agent for protocol 2 key operations */
    private const int SSH2_AGENTC_REQUEST_IDENTITIES = 11;
    private const int SSH2_AGENTC_SIGN_REQUEST = 13;
    private const int SSH2_AGENTC_ADD_IDENTITY = 17;
    private const int SSH2_AGENTC_REMOVE_IDENTITY = 18;
    private const int SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
    private const int SSH2_AGENTC_ADD_ID_CONSTRAINED = 25;

    /* Key-type independent requests from client to agent */
    private const int SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
    private const int SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;
    private const int SSH_AGENTC_LOCK = 22;
    private const int SSH_AGENTC_UNLOCK = 23;
    private const int SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;

    /* Generic replies from agent to client */
    private const int SSH_AGENT_FAILURE = 5;
    private const int SSH_AGENT_SUCCESS = 6;

    /* Replies from agent to client for protocol 1 key operations */
    private const int SSH1_AGENT_RSA_IDENTITIES_ANSWER = 2;
    private const int SSH1_AGENT_RSA_RESPONSE = 4;

    /* Replies from agent to client for protocol 2 key operations */
    private const int SSH2_AGENT_IDENTITIES_ANSWER = 12;
    private const int SSH2_AGENT_SIGN_RESPONSE = 14;

    /* Key constraint identifiers */
    private const int SSH_AGENT_CONSTRAIN_LIFETIME = 1;
    private const int SSH_AGENT_CONSTRAIN_CONFIRM = 2;

    /* not official */
    private const int SSH_AGENT_BAD_REQUEST = -1;


    /* variables */
    GetSSH2KeyListCallback mGetSSH2KeyListCallback;
    GetSSH2KeyCallback mGetSSH2KeyCallback;
    AddSSH2KeyCallback mAddSSH2KeyCallback;


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
      byte[] blobLengthBytes = new byte[4];
      aMessageStream.Read(blobLengthBytes, 0, 4);
      int msgDataLength = PSUtil.BytesToInt(blobLengthBytes, 0);
      int type;

      if (msgDataLength > 0) {
        type = aMessageStream.ReadByte();
      } else {
        type = SSH_AGENT_BAD_REQUEST;
      }

      switch (type) {
        case SSH1_AGENTC_REQUEST_RSA_IDENTITIES:
          /*
           * Reply with SSH1_AGENT_RSA_IDENTITIES_ANSWER.
           */

          // TODO implement SSH1_AGENT_RSA_IDENTITIES_ANSWER

          goto default; // failed
        case SSH2_AGENTC_REQUEST_IDENTITIES:
          /*
           * Reply with SSH2_AGENT_IDENTITIES_ANSWER.
           */
          if (mGetSSH2KeyListCallback == null) {
            Debug.Fail("no callback in SSH2_AGENTC_REQUEST_IDENTITIES");
            goto default; // can't reply without callback
          }
          PpkKeyBlobBuilder builder = new PpkKeyBlobBuilder();
          try {
            int keyCount = 0;

            foreach (PpkKey key in mGetSSH2KeyListCallback()) {
              keyCount++;
              builder.AddBlob(key.GetSSH2PublicKeyBlob());
              builder.AddString(key.Comment);
              key.Dispose();
            }
            if (aMessageStream.Length < 9 + builder.Length) {
              Debug.Fail("Not enough room in buffer in SSH2_AGENTC_REQUEST_IDENTITIES");
              goto default;
            }
            aMessageStream.Position = 0;
            aMessageStream.Write(PSUtil.IntToBytes(5 + builder.Length), 0, 4);
            aMessageStream.WriteByte(SSH2_AGENT_IDENTITIES_ANSWER);
            aMessageStream.Write(PSUtil.IntToBytes(keyCount), 0, 4);
            aMessageStream.Write(builder.getBlob(), 0, builder.Length);
            break; // succeeded            
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          } finally {
            builder.Clear();
          }
          goto default; // failed
        case SSH1_AGENTC_RSA_CHALLENGE:
          /*
           * Reply with either SSH1_AGENT_RSA_RESPONSE or
           * SSH_AGENT_FAILURE, depending on whether we have that key
           * or not.
           */

          // TODO implement SSH1_AGENTC_RSA_CHALLENGE

          goto default; // failed
        case SSH2_AGENTC_SIGN_REQUEST:
          /*
           * Reply with either SSH2_AGENT_SIGN_RESPONSE or SSH_AGENT_FAILURE,
           * depending on whether we have that key or not.
           */
          if (mGetSSH2KeyCallback == null) {
            Debug.Fail("No callback for SSH2_AGENTC_SIGN_REQUEST");
            goto default; // can't reply without callback
          }
          try {
            /* read rest of message */

            if (msgDataLength < aMessageStream.Position + 4) {
              Debug.Fail("incomplete message in SSH2_AGENTC_SIGN_REQUEST");
              goto default;
            }
            aMessageStream.Read(blobLengthBytes, 0, 4);
            int keyBlobLength = PSUtil.BytesToInt(blobLengthBytes, 0);
            if (msgDataLength < aMessageStream.Position + keyBlobLength) {
              Debug.Fail("incomplete message in SSH2_AGENTC_SIGN_REQUEST");
              goto default;
            }
            byte[] keyBlob = new byte[keyBlobLength];
            aMessageStream.Read(keyBlob, 0, keyBlobLength);
            if (msgDataLength < aMessageStream.Position + 4) {
              Debug.Fail("incomplete message in SSH2_AGENTC_SIGN_REQUEST");
              goto default;
            }
            aMessageStream.Read(blobLengthBytes, 0, 4);
            int reqDataLength = PSUtil.BytesToInt(blobLengthBytes, 0);
            if (msgDataLength < aMessageStream.Position + reqDataLength) {
              Debug.Fail("incomplete message in SSH2_AGENTC_SIGN_REQUEST");
              goto default;
            }
            byte[] reqData = new byte[reqDataLength];
            aMessageStream.Read(reqData, 0, reqDataLength);

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

              ISigner signer = null;
              string algName = null;
              if (key.KeyParameters.Public is RsaKeyParameters) {
                signer = SignerUtilities.GetSigner("SHA-1withRSA");
                algName = PpkKey.PublicKeyAlgorithms.ssh_rsa;
              }
              if (key.KeyParameters.Public is DsaPublicKeyParameters) {
                signer = SignerUtilities.GetSigner("SHA-1withDSA");
                algName = PpkKey.PublicKeyAlgorithms.ssh_dss;
              }
              if (signer == null) {
                Debug.Fail("unsupported algorithm in SSH2_AGENTC_SIGN_REQUEST");
                goto default;
              }
              signer.Init(true, key.KeyParameters.Private);
              signer.BlockUpdate(reqData, 0, reqData.Length);
              byte[] signature = signer.GenerateSignature();

              PpkKeyBlobBuilder sigBlobBuilder = new PpkKeyBlobBuilder();
              sigBlobBuilder.AddString(algName);
              sigBlobBuilder.AddBlob(signature);
              signature = sigBlobBuilder.getBlob();
              sigBlobBuilder.Clear();

              if (aMessageStream.Length < 9 + signature.Length) {
                Debug.Fail("Not enough room in buffer in SSH2_AGENTC_SIGN_REQUEST");
                goto default;
              }

              /* write response to filemap */

              aMessageStream.Position = 0;
              aMessageStream.Write(PSUtil.IntToBytes(5 + signature.Length), 0, 4);
              aMessageStream.WriteByte(SSH2_AGENT_SIGN_RESPONSE);
              aMessageStream.Write(PSUtil.IntToBytes(signature.Length), 0, 4);
              aMessageStream.Write(signature, 0, signature.Length);
              break; // succeeded
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failure
        case SSH1_AGENTC_ADD_RSA_IDENTITY:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          // TODO implement SSH1_AGENTC_ADD_RSA_IDENTITY

          goto default; // failed
        case SSH2_AGENTC_ADD_IDENTITY:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          if (mAddSSH2KeyCallback == null) {
            Debug.Fail("No callback for SSH2_AGENTC_ADD_IDENTITY");
            goto default; // can't reply without callback
          }
          try {
            /* read rest of message */

            if (msgDataLength < aMessageStream.Position + 4) {
              Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
              goto default;
            }
            aMessageStream.Read(blobLengthBytes, 0, 4);
            int algorithmLength = PSUtil.BytesToInt(blobLengthBytes, 0);
            if (msgDataLength < aMessageStream.Position + algorithmLength) {
              Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
              goto default;
            }
            byte[] blobBuffer = new byte[aMessageStream.Length];
            Array.Copy(blobLengthBytes, blobBuffer, blobLengthBytes.Length);
            aMessageStream.Read(blobBuffer, 5, algorithmLength);
            string algorithm = Encoding.UTF8.GetString(blobBuffer, 5, algorithmLength);
            PpkKey key = new PpkKey();
            int publicKeyBlobCount, privateKeyBlobCount;
            if (algorithm == PpkKey.PublicKeyAlgorithms.ssh_rsa) {
              publicKeyBlobCount = 2;
              privateKeyBlobCount = 4;
            } else if (algorithm == PpkKey.PublicKeyAlgorithms.ssh_dss) {
              publicKeyBlobCount = 4;
              privateKeyBlobCount = 1;
            } else {
              Debug.Fail("unsupported algorithm in SSH2_AGENTC_ADD_IDENTITY");
              goto default;
            }

            /* read public key data */
            int bufferPosition = 5 + algorithmLength;
            for (int i = 1; i < publicKeyBlobCount; i++) {
              if (msgDataLength < aMessageStream.Position + 4) {
                Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
                goto default;
              }
              aMessageStream.Read(blobLengthBytes, 0, 4);
              int blobLength = PSUtil.BytesToInt(blobLengthBytes, 0);
              if (msgDataLength < aMessageStream.Position + blobLength) {
                Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
                goto default;
              }
              Array.Copy(blobLengthBytes, 0, blobBuffer, bufferPosition, blobLengthBytes.Length);
              bufferPosition += blobLengthBytes.Length;
              aMessageStream.Read(blobBuffer, bufferPosition, blobLength);
              bufferPosition += blobLength;
            }
            byte[] publicKeyBlob = new byte[bufferPosition];
            Array.Copy(blobBuffer, publicKeyBlob, publicKeyBlob.Length);

            /* read private key data */
            bufferPosition = 0;
            for (int i = 1; i < privateKeyBlobCount; i++) {
              if (msgDataLength < aMessageStream.Position + 4) {
                Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
                goto default;
              }
              aMessageStream.Read(blobLengthBytes, 0, 4);
              int blobLength = PSUtil.BytesToInt(blobLengthBytes, 0);
              if (msgDataLength < aMessageStream.Position + blobLength) {
                Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
                goto default;
              }
              Array.Copy(blobLengthBytes, 0, blobBuffer, bufferPosition, blobLengthBytes.Length);
              bufferPosition += blobLengthBytes.Length;
              aMessageStream.Read(blobBuffer, bufferPosition, blobLength);
              bufferPosition += blobLength;
            }
            byte[] privateKeyBlob = new byte[bufferPosition];
            Array.Copy(blobBuffer, privateKeyBlob, privateKeyBlob.Length);

            key.KeyParameters = PpkFile.CreateKeyParameters(algorithm,
              publicKeyBlob, privateKeyBlob);

            if (msgDataLength < aMessageStream.Position + 4) {
              Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
              goto default;
            }
            aMessageStream.Read(blobLengthBytes, 0, 4);
            int commentLength = PSUtil.BytesToInt(blobLengthBytes, 0);
            if (msgDataLength < aMessageStream.Position + commentLength) {
              Debug.Fail("incomplete message in SSH2_AGENTC_ADD_IDENTITY");
              goto default;
            }
            byte[] commentBytes = new byte[commentLength];
            aMessageStream.Read(commentBytes, 0, commentBytes.Length);
            string comment = Encoding.UTF8.GetString(commentBytes, 5, commentLength);
            key.Comment = comment;

            /* do callback */            
            if (mAddSSH2KeyCallback(key)) {
              aMessageStream.Position = 0;
              aMessageStream.Write(PSUtil.IntToBytes(1), 0, 4);
              aMessageStream.WriteByte(SSH_AGENT_SUCCESS);
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed
        case SSH1_AGENTC_REMOVE_RSA_IDENTITY:
          /*
           * Remove from the list and return SSH_AGENT_SUCCESS, or
           * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
           * start with.
           */

          // TODO implement SSH1_AGENTC_REMOVE_RSA_IDENTITY

          goto default; // failed
        case SSH2_AGENTC_REMOVE_IDENTITY:
          /*
           * Remove from the list and return SSH_AGENT_SUCCESS, or
           * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
           * start with.
           */

          // TODO implement SSH2_AGENTC_REMOVE_IDENTITY

          goto default; // failed
        case SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
          /*
           * Remove all SSH-1 keys. Always returns success.
           */

          // TODO implement SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES

          goto default; // failed
        case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
          /*
           * Remove all SSH-2 keys. Always returns success.
           */

          // TODO implement SSH2_AGENTC_REMOVE_ALL_IDENTITIES

          goto default; // failed

        case SSH_AGENT_BAD_REQUEST:
        default:
          aMessageStream.Position = 0;
          aMessageStream.Write(PSUtil.IntToBytes(1), 0, 4);
          aMessageStream.WriteByte(SSH_AGENT_FAILURE);
          break;
      }
    }

    public virtual void Dispose()
    {

    }
  }
}

