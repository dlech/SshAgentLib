//
// Agent.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2015,2017-2018 David Lechner
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
using System.Timers;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Implements OpenSSH Agent
  /// </summary>
  /// <remarks>
  /// Inheriting classes should implement the platform specific communication
  /// to get a message from a client and then call AnswerMessage method
  /// </remarks>
  public abstract class Agent : IAgent, IDisposable
  {
    #region Instance Variables

    private List<ISshKey> mKeyList;
    private SecureString mLockedPassphrase;

    #endregion

    #region Events

    /// <summary>
    /// fired when agent is locked or unlocked
    /// </summary>
    public event LockEventHandler Locked;

    /// <summary>
    /// fired when a key is added or removed
    /// </summary>
    public event SshKeyEventHandler KeyAdded;

    /// <summary>
    /// fired when a key is added or removed
    /// </summary>
    public event SshKeyEventHandler KeyRemoved;

    /// <summary>
    /// fired when a message is received by the agent
    /// </summary>
    public event MessageReceivedEventHandler MessageReceived;

    /// <summary>
    /// fired when a key is used to sign a request
    /// </summary>
    public event KeyUsedEventHandler KeyUsed;

    #endregion

    #region Enums

    /* Protocol message number - from PROTOCOL.agent in OpenSSH source code */
    /* note: changed SSH_* to SSH1_* on protocol v1 specific items for clarity */
    public enum Message : byte
    {
      /* Requests from client to agent for protocol 1 key operations */
      SSH1_AGENTC_REQUEST_RSA_IDENTITIES = 1,
      SSH1_AGENTC_RSA_CHALLENGE = 3,
      SSH1_AGENTC_ADD_RSA_IDENTITY = 7,
      SSH1_AGENTC_REMOVE_RSA_IDENTITY = 8,
      SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9,
      SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED = 24,

      /* Requests from client to agent for protocol 2 key operations */
      SSH2_AGENTC_REQUEST_IDENTITIES = 11,
      SSH2_AGENTC_SIGN_REQUEST = 13,
      SSH2_AGENTC_ADD_IDENTITY = 17,
      SSH2_AGENTC_REMOVE_IDENTITY = 18,
      SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19,
      SSH2_AGENTC_ADD_ID_CONSTRAINED = 25,

      /* Key-type independent requests from client to agent */
      SSH_AGENTC_ADD_SMARTCARD_KEY = 20,
      SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21,
      SSH_AGENTC_LOCK = 22,
      SSH_AGENTC_UNLOCK = 23,
      SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26,

      /* Generic replies from agent to client */
      SSH_AGENT_FAILURE = 5,
      SSH_AGENT_SUCCESS = 6,

      /* Replies from agent to client for protocol 1 key operations */
      SSH1_AGENT_RSA_IDENTITIES_ANSWER = 2,
      SSH1_AGENT_RSA_RESPONSE = 4,

      /* Replies from agent to client for protocol 2 key operations */
      SSH2_AGENT_IDENTITIES_ANSWER = 12,
      SSH2_AGENT_SIGN_RESPONSE = 14,

      /* Extensions */
      SSH_AGENTC_EXTENSION = 27,
      SSH_AGENT_EXTENSION_FAILURE = 28,

      UNKNOWN = 255
    }

    public enum KeyConstraintType : byte
    {
      /* Key constraint identifiers */
      SSH_AGENT_CONSTRAIN_LIFETIME = 1,
      SSH_AGENT_CONSTRAIN_CONFIRM = 2,
      SSH_AGENT_CONSTRAIN_EXTENSION = 3,
    }

    [Flags]
    public enum SignRequestFlags : uint
    {
      SSH_AGENT_OLD_SIGNATURE = 0x01,
      SSH_AGENT_RSA_SHA2_256 = 0x02,
      SSH_AGENT_RSA_SHA2_512 = 0x04,
    }

    #endregion

    #region Data Types

    public struct KeyConstraint
    {
      private object mData;

      public KeyConstraintType Type { get; set; }
      public Object Data
      {
        get
        {
          return mData;
        }
        set
        {
          if (value.GetType() != Type.GetDataType()) {
            throw new Exception("Incorrect data type");
          }
          mData = value;
        }
      }
    }

    public struct BlobHeader
    {
      public UInt32 BlobLength { get; set; }
      public Agent.Message Message { get; set; }
    }

    public class LockEventArgs : EventArgs
    {
      public LockEventArgs(bool aIsLocked)
      {
        IsLocked = aIsLocked;
      }
      public bool IsLocked { get; private set; }
    }

    /// <summary>
    /// Handles events when Agent is locked and unlocked
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="e"></param>
    public delegate void LockEventHandler(object sender, LockEventArgs e);

    public class MessageReceivedEventArgs : EventArgs
    {
      public MessageReceivedEventArgs(BlobHeader aMessageHeader)
      {
        MessageHeader = aMessageHeader;
        Fail = false;
      }

      /// <summary>
      /// The message header of the message
      /// </summary>
      public BlobHeader MessageHeader { get; private set; }

      /// <summary>
      /// Setting to true causes the message to not be processed.
      /// The agent will return SSH_AGENT_FAILURE
      /// </summary>
      public bool Fail { get; set; }
    }

    public delegate void MessageReceivedEventHandler(object sender, MessageReceivedEventArgs e);

    public class KeyUsedEventArgs : EventArgs
    {
      public ISshKey Key { get; private set; }
      public Process OtherProcess { get; private set; }

      public KeyUsedEventArgs(ISshKey key, Process otherProcess)
      {
        Key = key;
        OtherProcess = otherProcess;
      }
    }

    public delegate void KeyUsedEventHandler(object sender, KeyUsedEventArgs e);

    /// <summary>
    /// Requests user for permission to use specified key.
    /// </summary>
    /// <param name="key">The key that will be used</param>
    /// <param name="process">The calling process or <c>null</c> if the
    /// process could not be obtained.</param>
    /// <returns>
    /// true if user grants permission, false if user denies permission
    /// </returns>
    public delegate bool ConfirmUserPermissionDelegate(ISshKey key, Process process);

    /// <summary>
    /// Filters the list of keys that will be returned by the request identities
    /// messages.
    /// </summary>
    /// <param name="keyList">The list of keys to filter.</param>
    /// <returns>A filtered list of keys.</returns>
    public delegate ICollection<ISshKey> FilterKeyListDelegate(ICollection<ISshKey> keyList);

    #endregion

    #region Properties

    /// <summary>
    /// true if agent is locked
    /// </summary>
    public bool IsLocked { get; private set; }

    public int KeyCount { get { return mKeyList.Count; } }

    public ConfirmUserPermissionDelegate ConfirmUserPermissionCallback { get; set; }

    public FilterKeyListDelegate FilterKeyListCallback { get; set; }

    #endregion

    #region Constructors

    protected Agent()
    {
      mKeyList = new List<ISshKey>();
    }

    #endregion

    #region Public Methods

    public void AddKey(ISshKey key)
    {
      if (IsLocked) {
        throw new AgentLockedException();
      }

      /* handle constraints */

      foreach (KeyConstraint constraint in key.Constraints) {
        if (constraint.Type ==
                  KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM &&
                  ConfirmUserPermissionCallback == null) {
          // can't add key with confirm constraint if we don't have
          // confirm callback
          throw new CallbackNullException();
        }
        if (constraint.Type ==
            Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME) {
          UInt32 lifetime = (UInt32)constraint.Data * 1000;
          Timer timer = new Timer(lifetime);
          ElapsedEventHandler onTimerElapsed = null;
          onTimerElapsed = (s, e) =>
            {
              timer.Elapsed -= onTimerElapsed;
              RemoveKey(key);
            };
          timer.Elapsed += onTimerElapsed;
          timer.Start();
        }
      }

      /* first remove matching key if it exists */
      ISshKey matchingKey = mKeyList.Get(key.Version, key.GetPublicKeyBlob());
      RemoveKey(matchingKey);

      mKeyList.Add(key);
      FireKeyAdded(key);
    }

    public void RemoveKey(ISshKey key)
    {
      if (IsLocked) {
        throw new AgentLockedException();
      }

      if (mKeyList.Remove(key)) {
        FireKeyRemoved(key);
      }
    }

    public void RemoveAllKeys(SshVersion aVersion)
    {
      if (IsLocked) {
        throw new AgentLockedException();
      }

      var removeKeyList = ListKeys(aVersion);
      foreach (ISshKey key in removeKeyList) {
        RemoveKey(key);
      }
    }

    public ICollection<ISshKey> ListKeys(SshVersion aVersion)
    {
      if (IsLocked) {
        return new List<ISshKey>();
      }
      return mKeyList.Where(key => key.Version == aVersion).ToList();
    }

    public void Lock(byte[] aPassphrase)
    {
      if (IsLocked) {
        // can't lock if already locked
        throw new AgentLockedException();
      }
      mLockedPassphrase = new SecureString();
      if (aPassphrase != null) {
        foreach (byte b in aPassphrase) {
          mLockedPassphrase.AppendChar((char)b);
        }
      }
      IsLocked = true;
      FireLocked();
    }

    public void Unlock(byte[] aPassphrase)
    {
      if (!IsLocked) {
        // can't unlock if not locked
        throw new AgentLockedException();
      }
      if (aPassphrase == null) {
        aPassphrase = new byte[0];
      }
      if (mLockedPassphrase.Length != aPassphrase.Length) {
        // passwords definitely do not match
        throw new PassphraseException();
      }
      IntPtr lockedPassPtr =
          Marshal.SecureStringToGlobalAllocUnicode(mLockedPassphrase);
      for (int i = 0; i < mLockedPassphrase.Length; i++) {
        Int16 lockedPassChar = Marshal.ReadInt16(lockedPassPtr, i * 2);
        if (lockedPassChar != aPassphrase[i]) {
          Marshal.ZeroFreeGlobalAllocUnicode(lockedPassPtr);
          throw new PassphraseException();
        }
      }
      Marshal.ZeroFreeGlobalAllocUnicode(lockedPassPtr);
      mLockedPassphrase.Clear();
      IsLocked = false;
      FireLocked();
    }

    /// <summary>
    /// Answers the message.
    /// </summary>
    /// <param name='messageStream'>Message stream.</param>
    /// <param name="process">The calling process or <c>null</c> if the process
    /// could not be obtained.</param>
    /// <remarks>code based on winpgnt.c from PuTTY source code</remarks>
    public void AnswerMessage(Stream messageStream, Process process = null)
    {
      if (messageStream.CanTimeout) {
        messageStream.ReadTimeout = 5000;
      }
      var messageParser = new BlobParser(messageStream);
      var responseBuilder = new BlobBuilder();
      BlobHeader header;
      try {
        header = messageParser.ReadHeader();

        if (MessageReceived != null) {
          var eventArgs = new MessageReceivedEventArgs(header);
          MessageReceived(this, eventArgs);
          if (eventArgs.Fail) {
            throw new Exception ();
          }
        }
      } catch (Exception) {
        header = new BlobHeader();
        header.Message = Message.UNKNOWN;
        // this will cause the switch statement below to use the default case
        // which returns an error to the stream.
      }

      switch (header.Message) {
        case Message.SSH1_AGENTC_REQUEST_RSA_IDENTITIES:
          /*
           * Reply with SSH1_AGENT_RSA_IDENTITIES_ANSWER.
           */
          try {
            if (header.BlobLength > 1) {
              // ruby net-ssh tries to send a SSH2_AGENT_REQUEST_VERSION message
              // which has the same id number as SSH1_AGENTC_REQUEST_RSA_IDENTITIES
              // with a string tacked on. We need to read the string from the
              // stream, but it is not used for anything.
              messageParser.ReadString ();
            }
            var keyList = ListKeys(SshVersion.SSH1);
            if (FilterKeyListCallback != null) {
              keyList = FilterKeyListCallback(keyList);
            }
            foreach (SshKey key in keyList) {
              responseBuilder.AddBytes(key.GetPublicKeyBlob());
              responseBuilder.AddStringBlob(key.Comment);
            }
            responseBuilder.InsertHeader(Message.SSH1_AGENT_RSA_IDENTITIES_ANSWER,
              keyList.Count);
            // TODO may want to check that there is enough room in the message stream
            break; // succeeded
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case Message.SSH2_AGENTC_REQUEST_IDENTITIES:
          /*
           * Reply with SSH2_AGENT_IDENTITIES_ANSWER.
           */
          try {
            var keyList = ListKeys(SshVersion.SSH2);
            if (FilterKeyListCallback != null) {
              keyList = FilterKeyListCallback(keyList);
            }
            foreach (SshKey key in keyList) {
              responseBuilder.AddBlob(key.GetPublicKeyBlob());
              responseBuilder.AddStringBlob(key.Comment);
            }
            responseBuilder.InsertHeader(Message.SSH2_AGENT_IDENTITIES_ANSWER,
              keyList.Count);
            // TODO may want to check that there is enough room in the message stream
            break; // succeeded
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case Message.SSH1_AGENTC_RSA_CHALLENGE:
          /*
           * Reply with either SSH1_AGENT_RSA_RESPONSE or
           * SSH_AGENT_FAILURE, depending on whether we have that key
           * or not.
           */

          try {
            //Reading publicKey information
            var publicKeyParams = messageParser.ReadSsh1PublicKeyData(true);

            //Searching for Key here
            var matchingKey = mKeyList.Where(key => key.Version == SshVersion.SSH1
                && (key.GetPublicKeyParameters().Equals(publicKeyParams))).Single();

            //Reading challenge
            var encryptedChallenge = messageParser.ReadSsh1BigIntBlob();
            var sessionId = messageParser.ReadBytes(16);

            //Checking responseType field
            if (messageParser.ReadUInt32() != 1) {
              goto default; //responseType !=1  is not longer supported
            }

            //Answering to the challenge
            var engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(false /* decrypt */, matchingKey.GetPrivateKeyParameters());

            var decryptedChallenge = engine.ProcessBlock(encryptedChallenge,
                0, encryptedChallenge.Length);

            using (MD5 md5 = MD5.Create()) {
              var md5Buffer = new byte[48];
              decryptedChallenge.CopyTo(md5Buffer, 0);
              sessionId.CopyTo(md5Buffer, 32);

              responseBuilder.AddBytes(md5.ComputeHash(md5Buffer));
              responseBuilder.InsertHeader(Message.SSH1_AGENT_RSA_RESPONSE);
              break;
            }
          } catch (InvalidOperationException) {
            // this is expected if there is not a matching key
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }

          goto default; // failed

        case Message.SSH2_AGENTC_SIGN_REQUEST:
          /*
           * Reply with either SSH2_AGENT_SIGN_RESPONSE or SSH_AGENT_FAILURE,
           * depending on whether we have that key or not.
           */
          try {
            var keyBlob = messageParser.ReadBlob();
            var reqData = messageParser.ReadBlob();
            var flags = new SignRequestFlags();
            try {
              // usually, there are no flags, so parser will throw
              flags = (SignRequestFlags)messageParser.ReadUInt32();
            } catch { }

            var matchingKey =
              mKeyList.Where(key => key.Version == SshVersion.SSH2 &&
              key.GetPublicKeyBlob().SequenceEqual(keyBlob)).First();
            var confirmConstraints = matchingKey.Constraints
              .Where(constraint => constraint.Type ==
                KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
            if (confirmConstraints.Count() > 0) {
              if (!ConfirmUserPermissionCallback.Invoke(matchingKey, process)) {
                goto default;
              }
            }

            /* create signature */
            var signKey = matchingKey;
            var signer = signKey.GetSigner(flags);
            signer.Init(true, signKey.GetPrivateKeyParameters());
            signer.BlockUpdate(reqData, 0, reqData.Length);
            byte[] signature = signer.GenerateSignature();
            signature = signKey.FormatSignature(signature);
            BlobBuilder signatureBuilder = new BlobBuilder();

            if (!flags.HasFlag(SignRequestFlags.SSH_AGENT_OLD_SIGNATURE)) {
              var algName = signKey.Algorithm.GetIdentifierString();

              // handle possible overridden signer (because of flags)
              if (signer.AlgorithmName == "SHA-512withRSA") {
                algName = "rsa-sha2-512";
              }
              else if (signer.AlgorithmName == "SHA-256withRSA") {
                algName = "rsa-sha2-256";
              }

              signatureBuilder.AddStringBlob(algName);
            }

            signatureBuilder.AddBlob(signature);
            responseBuilder.AddBlob(signatureBuilder.GetBlob());
            responseBuilder.InsertHeader(Message.SSH2_AGENT_SIGN_RESPONSE);
            try {
              KeyUsed(this, new KeyUsedEventArgs(signKey, process));
            } catch { }
            break; // succeeded
          } catch (InvalidOperationException) {
            // this is expected if there is not a matching key
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failure

        case Message.SSH1_AGENTC_ADD_RSA_IDENTITY:
        case Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          if (IsLocked) {
            goto default;
          }

          bool ssh1constrained = (header.Message == Message.SSH1_AGENTC_ADD_RSA_ID_CONSTRAINED);

          try {
            var publicKeyParams = messageParser.ReadSsh1PublicKeyData(false);
            var keyPair = messageParser.ReadSsh1KeyData(publicKeyParams);

            SshKey key = new SshKey(SshVersion.SSH1, keyPair);
            key.Comment = messageParser.ReadString();
            key.Source = "External client";

            if (ssh1constrained) {
              while (messageStream.Position < header.BlobLength + 4) {
                KeyConstraint constraint = new KeyConstraint();
                constraint.Type = (KeyConstraintType)messageParser.ReadUInt8();
                if (constraint.Type ==
                  KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME) {
                  constraint.Data = messageParser.ReadUInt32();
                }
                key.AddConstraint(constraint);
              }
            }
            AddKey(key);
            responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
            break;

          } catch (CallbackNullException) {
            // this is expected
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }

          goto default; // failed

        case Message.SSH2_AGENTC_ADD_IDENTITY:
        case Message.SSH2_AGENTC_ADD_ID_CONSTRAINED:
          /*
           * Add to the list and return SSH_AGENT_SUCCESS, or
           * SSH_AGENT_FAILURE if the key was malformed.
           */

          if (IsLocked) {
            goto default;
          }

          bool constrained = (header.Message ==
              Message.SSH2_AGENTC_ADD_ID_CONSTRAINED);

          try {
            OpensshCertificate cert;
            var publicKeyParams = messageParser.ReadSsh2PublicKeyData(out cert);
            var keyPair = messageParser.ReadSsh2KeyData(publicKeyParams);
            SshKey key = new SshKey(SshVersion.SSH2, keyPair, null, cert);
            key.Comment = messageParser.ReadString();
            key.Source = "External client";

            if (constrained) {
              while (messageStream.Position < header.BlobLength + 4) {
                KeyConstraint constraint = new KeyConstraint();
                constraint.Type =
                  (KeyConstraintType)messageParser.ReadUInt8();
                if (constraint.Type ==
                  KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME) {
                  constraint.Data = messageParser.ReadUInt32();
                }
                key.AddConstraint(constraint);
              }
            }
            AddKey(key);
            responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
            break; // success!            
          } catch (CallbackNullException) {
            // this is expected
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY:
        case Message.SSH2_AGENTC_REMOVE_IDENTITY:
          /*
           * Remove from the list and return SSH_AGENT_SUCCESS, or
           * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
           * start with.
           */

          if (IsLocked) {
            goto default;
          }

          SshVersion removeVersion;
          byte[] rKeyBlob;
          if (header.Message == Message.SSH1_AGENTC_REMOVE_RSA_IDENTITY) {
            removeVersion = SshVersion.SSH1;
            rKeyBlob = messageParser.ReadBytes(header.BlobLength - 1);
          } else if (header.Message == Message.SSH2_AGENTC_REMOVE_IDENTITY) {
            removeVersion = SshVersion.SSH2;
            rKeyBlob = messageParser.ReadBlob();
          } else {
            Debug.Fail("Should not get here.");
            goto default;
          }

          try {
            var matchingKey = mKeyList.Get(removeVersion, rKeyBlob);
            var startKeyListLength = mKeyList.Count;
            RemoveKey(matchingKey);
            // only succeed if key was removed
            if (mKeyList.Count == startKeyListLength - 1) {
              responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
              break; //success!
            }
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case Message.SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
        case Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
          /*
           * Remove all SSH-1 or SSH-2 keys.
           */

          if (IsLocked) {
            goto default;
          }

          SshVersion removeAllVersion;
          if (header.Message == Message.SSH1_AGENTC_REMOVE_ALL_RSA_IDENTITIES) {
            removeAllVersion = SshVersion.SSH1;
          } else if (header.Message == Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES) {
            removeAllVersion = SshVersion.SSH2;
          } else {
            Debug.Fail("Should not get here.");
            goto default;
          }

          try {
            RemoveAllKeys(removeAllVersion);
            responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
            break; //success!
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default; // failed

        case Message.SSH_AGENTC_LOCK:
          try {
            var passphrase = new PinnedArray<byte>(messageParser.ReadBlob());
            try {
              Lock(passphrase.Data);
            } finally {
              passphrase.Clear();
            }
            if (IsLocked) {
              responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
              break;
            }
          } catch (AgentLockedException) {
            // This is expected
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default;

        case Message.SSH_AGENTC_UNLOCK:
          try {
            var passphrase = new PinnedArray<byte>(messageParser.ReadBlob());
            try {
              Unlock(passphrase.Data);
            } finally {
              passphrase.Clear();
            }
            if (!IsLocked) {
              responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
              break;
            }
          } catch (AgentLockedException) {
            // This is expected
          } catch (PassphraseException) {
            // This is expected
          } catch (Exception ex) {
            Debug.Fail(ex.ToString());
          }
          goto default;

        default:
          responseBuilder.Clear();
          responseBuilder.InsertHeader(Message.SSH_AGENT_FAILURE);
          break;
      }
      /* write response to stream */
      if (messageStream.CanSeek)
        messageStream.Position = 0;
      messageStream.Write(responseBuilder.GetBlob(), 0, responseBuilder.Length);
      messageStream.Flush();
    }

    public abstract void Dispose();

    #endregion

    #region Private Methods

    private void FireKeyAdded(ISshKey key)
    {
      if (KeyAdded != null) {
        SshKeyEventArgs args = new SshKeyEventArgs(key);
        KeyAdded(this, args);
      }
    }

    private void FireKeyRemoved(ISshKey key)
    {
      if (KeyRemoved != null) {
        SshKeyEventArgs args = new SshKeyEventArgs(key);
        KeyRemoved(this, args);
      }
    }

    /// <summary>
    /// Fires lock event for listeners
    /// </summary>
    private void FireLocked()
    {
      if (Locked != null) {
        LockEventArgs args = new LockEventArgs(IsLocked);
        Locked(this, args);
      }
    }

    #endregion
  }
}

