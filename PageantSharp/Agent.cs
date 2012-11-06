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
    private Callbacks mCallbacks;
    private string mLockedPassphrase; // TODO use SecureString here
    #endregion


    public class LockEventArgs : EventArgs
    {
      public LockEventArgs(bool aIsLocked)
      {
        IsLocked = aIsLocked;
      }
      public bool IsLocked { get; private set; }
    }

    public delegate void LockEventHandler(object aSender, LockEventArgs aEventArgs);

    public event LockEventHandler Locked;

    /// <summary>
    /// true if agent is locked
    /// </summary>
    public bool IsLocked { get; private set; }

    private void OnLocked()
    {
      if (Locked != null) {
        LockEventArgs args = new LockEventArgs(IsLocked);
        Locked(this, args);
      }
    }

    public bool Lock(string aPassphrase)
    {
      if (IsLocked) {
        // can't lock if already locked
        return false;
      }
      mLockedPassphrase = aPassphrase;
      IsLocked = true;
      OnLocked();
      return true;
    }

    public bool Unlock(string aPassphrase)
    {
      if (!IsLocked) {
        // can't unlock if not locked
        return false;
      }
      if (mLockedPassphrase != aPassphrase) {
        // bad passphrase
        return false;
      }
      IsLocked = false;
      OnLocked();
      return true;
    }

    /// <summary>
    /// Implementer should return a list of public keys that will be
    /// sent to a remote client
    /// </summary>
    /// <returns>List of PpkKey objects. Keys will be disposed by callback,
    /// so a new list should be created on each call</returns>
    public delegate IEnumerable<SshKey> GetSSHKeyListCallback();

    /// <summary>
    /// Implementer should return the specific key that matches the fingerprint.
    /// </summary>
    /// <param name="fingerprint">MD5 fingerprint of key</param>
    /// <returns>
    /// PpkKey object that matches fingerprint or null. Keys will be disposed by
    /// callback, so a new object should be created on each call
    /// </returns>
    public delegate SshKey GetSSHKeyCallback(byte[] aFingerprint);

    /// <summary>
    /// Implementer should Add the specified key to its key store
    /// </summary>
    /// <param name="aKey">The PpkKey to add to storage</param>
    /// <returns>
    /// True if key was added successfully.
    /// </returns>
    public delegate bool AddSSHKeyCallback(SshKey aKey);

    /// <summary>
    /// Implementer should Add the specified key to its key store with specified
    /// constraints.
    /// </summary>
    /// <param name="aKey">The PpkKey to add to storage</param>
    /// <param name="aConstraints">List of constraints on the key.</param>
    /// <returns>
    /// True if key was added successfully.
    /// </returns>
    public delegate bool AddConstrainedSSHKeyCallback(SshKey aKey,
      IList<OpenSsh.KeyConstraint> aConstraints);

    /// <summary>
    /// Implementer should remove the specified key from its key store
    /// </summary>
    /// <param name="aFingerprint">MD5 fingerprint of key</param>
    /// <returns>true if key was removed</returns>
    public delegate bool RemoveSSHKeyCallback(byte[] aFingerprint);

    /// <summary>
    /// Implementer should remove all keys from its key store
    /// </summary>
    /// <returns>true if all keys were removed</returns>
    public delegate bool RemoveAllSSHKeysCallback();


    public struct Callbacks
    {
      public GetSSHKeyListCallback getSSH1KeyList;
      public GetSSHKeyCallback getSSH1Key;
      public AddSSHKeyCallback addSSH1Key;
      public AddConstrainedSSHKeyCallback addConstrainedSSH1Key;
      public RemoveSSHKeyCallback removeSSH1Key;
      public RemoveAllSSHKeysCallback removeAllSSH1Keys;
      public GetSSHKeyListCallback getSSH2KeyList;
      public GetSSHKeyCallback getSSH2Key;
      public AddSSHKeyCallback addSSH2Key;
      public AddConstrainedSSHKeyCallback addConstrainedSSH2Key;
      public RemoveSSHKeyCallback removeSSH2Key;
      public RemoveAllSSHKeysCallback removeAllSSH2Keys;
      public AddSSHKeyCallback addSmartkey;
      public AddConstrainedSSHKeyCallback addConstrainedSmartkey;
      public RemoveSSHKeyCallback removeConstrainedSmartkey;
    }

    public Agent(Callbacks aCallbacks)
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
      BlobParser messageParser = new BlobParser(aMessageStream);
      BlobBuilder responseBuilder = new BlobBuilder();

      OpenSsh.BlobHeader header = messageParser.ReadHeader();

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
          try {
            int keyCount = 0;
            if (!IsLocked) {
              foreach (SshKey key in mCallbacks.getSSH2KeyList()) {
                keyCount++;
                responseBuilder.AddBlob(OpenSsh.GetSSH2PublicKeyBlob(key.CipherKeyPair));
                responseBuilder.AddString(key.Comment);
                key.Dispose();
              }
            }
            responseBuilder.InsertHeader(OpenSsh.Message.SSH2_AGENT_IDENTITIES_ANSWER,
              keyCount);
            // TODO may want to check that there is enough room in the message stream
            break; // succeeded
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          responseBuilder.Clear();
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
          if (IsLocked || mCallbacks.getSSH2Key == null) {
            goto default; // can't reply without callback
          }
          try {
            PinnedByteArray keyBlob = messageParser.ReadBlob();
            PinnedByteArray reqData = messageParser.ReadBlob();

            /* get matching key from callback */
            MD5 md5 = MD5.Create();
            byte[] fingerprint = md5.ComputeHash(keyBlob.Data);
            md5.Clear();
            using (SshKey key = mCallbacks.getSSH2Key(fingerprint)) {
              if (key == null) {
                goto default;
              }
              /* create signature */

              ISigner signer;
              string algName = key.Algorithm;
              if (key.CipherKeyPair.Public is RsaKeyParameters) {
                signer = SignerUtilities.GetSigner("SHA-1withRSA");
              } else if (key.CipherKeyPair.Public is DsaPublicKeyParameters) {
                signer = SignerUtilities.GetSigner("SHA-1withDSA");
              } else {
                goto default;
              }
              signer.Init(true, key.CipherKeyPair.Private);
              signer.BlockUpdate(reqData.Data, 0, reqData.Data.Length);
              byte[] signature = signer.GenerateSignature();

              responseBuilder.AddString(algName);
              responseBuilder.AddBlob(signature);
              responseBuilder.InsertHeader(OpenSsh.Message.SSH2_AGENT_SIGN_RESPONSE);
              // TODO may want to check that there is enough room in the message stream
              break; // succeeded
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          responseBuilder.Clear();
          goto default; // failure

        case OpenSsh.Message.SSH1_AGENTC_ADD_RSA_IDENTITY:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          // TODO implement SSH1_AGENTC_ADD_RSA_IDENTITY

          goto default; // failed

        case OpenSsh.Message.SSH2_AGENTC_ADD_IDENTITY:
        case OpenSsh.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          bool constrained = (header.Message ==
              OpenSsh.Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);

          if (IsLocked || (!constrained && mCallbacks.addSSH2Key == null) ||
            (constrained && mCallbacks.addConstrainedSSH2Key == null)) {
            goto default; // can't reply without callback
          }
          try {
            SshKey key = new SshKey();
            key.Version = SshVersion.SSH2;
            key.CipherKeyPair = OpenSsh.CreateCipherKeyPair(aMessageStream);
            key.Comment = messageParser.ReadString();

            List<OpenSsh.KeyConstraint> constraints = null;
            if (constrained) {
              constraints = new List<OpenSsh.KeyConstraint>();
              while (aMessageStream.Position < header.BlobLength) {
                try {
                  OpenSsh.KeyConstraint constraint = new OpenSsh.KeyConstraint();
                  constraint.Type =
                    (OpenSsh.KeyConstraintType)messageParser.ReadByte();
                  if (constraint.Type ==
                    OpenSsh.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME) {
                    constraint.Data = messageParser.ReadInt();
                  }
                  constraints.Add(constraint);
                } catch (Exception ex) {
                  Debug.Fail(ex.ToString());
                  goto default;
                }
              }
              /* do callback */
              if (mCallbacks.addConstrainedSSH2Key(key, constraints)) {
                responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_SUCCESS);
                break; // success!
              }
            }

            /* do callback */
            if (mCallbacks.addSSH2Key(key)) {
              responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_SUCCESS);
              break; // success!
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case OpenSsh.Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY:
        case OpenSsh.Message.SSH2_AGENTC_REMOVE_IDENTITY:
          /*
           * Remove from the list and return SSH_AGENT_SUCCESS, or
           * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
           * start with.
           */

          RemoveSSHKeyCallback removeSshKeyCallback;
          if (header.Message == OpenSsh.Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY) {
            removeSshKeyCallback = mCallbacks.removeSSH1Key;
          } else if (header.Message == OpenSsh.Message.SSH2_AGENTC_REMOVE_IDENTITY) {
            removeSshKeyCallback = mCallbacks.removeSSH2Key;
          } else {
            Debug.Fail("Should not get here.");
            goto default;
          }

          if (IsLocked || removeSshKeyCallback == null) {
            goto default;
          }

          try {
            PinnedByteArray rKeyBlob = messageParser.ReadBlob();

            /* get matching key from callback */
            MD5 rMd5 = MD5.Create();
            byte[] rFingerprint = rMd5.ComputeHash(rKeyBlob.Data);
            rMd5.Clear();

            if (removeSshKeyCallback(rFingerprint)) {
              responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_SUCCESS);
              break; //success!
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case OpenSsh.Message.SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
        case OpenSsh.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
          /*
           * Remove all SSH-1 or SSH-2 keys.
           */

          RemoveAllSSHKeysCallback removeAllSshKeysCallback;
          if (header.Message == OpenSsh.Message.SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES) {
            removeAllSshKeysCallback = mCallbacks.removeAllSSH1Keys;
          } else if (header.Message == OpenSsh.Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES) {
            removeAllSshKeysCallback = mCallbacks.removeAllSSH2Keys;
          } else {
            Debug.Fail("Should not get here.");
            goto default;
          }

          if (IsLocked || removeAllSshKeysCallback == null) {
            goto default;
          }

          try {
            if (removeAllSshKeysCallback()) {
              responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_SUCCESS);
              break; //success!
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case OpenSsh.Message.SSH_AGENTC_LOCK:
          try {
            string passphrase = messageParser.ReadString();
            if (Lock(passphrase)) {
              responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_SUCCESS);
              break;
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default;

        case OpenSsh.Message.SSH_AGENTC_UNLOCK:
          try {
            string passphrase = messageParser.ReadString();
            if (Unlock(passphrase)) {
              responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_SUCCESS);
              break;
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default;

        default:
          responseBuilder.InsertHeader(OpenSsh.Message.SSH_AGENT_FAILURE);
          break;
      }
      /* write response to stream */
      aMessageStream.Position = 0;
      aMessageStream.Write(responseBuilder.GetBlob(), 0, responseBuilder.Length);
    }

    public abstract void Dispose();
  }
}

