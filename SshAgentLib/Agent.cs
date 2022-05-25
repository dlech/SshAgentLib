// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2015,2017-2018,2022 David Lechner <david@lechnology.com>
// Author(s): David Lechner
//            Max Laverse

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Timers;
using SshAgentLib.Connection;
using SshAgentLib.Extension;
using SshAgentLib.Keys;

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

        private readonly List<ISshKey> keyList;
        private SecureString lockedPassphrase;

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
        public enum Message : byte
        {
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
            SSH_AGENT_CONSTRAIN_EXTENSION = 0xff,
        }

        [Flags]
        public enum SignRequestFlags : uint
        {
            SSH_AGENT_RSA_SHA2_256 = 0x02,
            SSH_AGENT_RSA_SHA2_512 = 0x04,
        }

        private const byte SSH2_MSG_USERAUTH_REQUEST = 50;

        #endregion

        #region Data Types

        public struct KeyConstraint
        {
            private object data;

            public KeyConstraintType Type { get; set; }

            public object Data
            {
                get { return data; }
                set
                {
                    if (value.GetType() != Type.GetDataType())
                    {
                        throw new Exception("Incorrect data type");
                    }
                    data = value;
                }
            }
        }

        public struct BlobHeader
        {
            public int BlobLength { get; set; }
            public Message Message { get; set; }
        }

        public class LockEventArgs : EventArgs
        {
            public LockEventArgs(bool isLocked)
            {
                IsLocked = isLocked;
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
            public MessageReceivedEventArgs(BlobHeader messageHeader)
            {
                MessageHeader = messageHeader;
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
        /// <param name="process">
        /// The calling process or <c>null</c> if the process could not be obtained.
        /// </param>
        /// <param name="user">
        /// The requested user name if available, otherwise <c>null</c>.
        /// </param>
        /// <param name="fromHostName">
        /// The requested source host name if available, otherwise <c>null</c>.
        /// </param>
        /// <param name="toHostName">
        /// The requested destination host name if available, otherwise <c>null</c>.
        /// </param>
        /// <returns>
        /// true if user grants permission, false if user denies permission
        /// </returns>
        public delegate bool ConfirmUserPermissionDelegate(
            ISshKey key,
            Process process,
            string user,
            string fromHostName,
            string toHostName
        );

        /// <summary>
        /// Filters the list of keys that will be returned by the request identities
        /// messages.
        /// </summary>
        /// <param name="keyList">The list of keys to filter.</param>
        /// <returns>A filtered list of keys.</returns>
        public delegate IEnumerable<ISshKey> FilterKeyListDelegate(IEnumerable<ISshKey> keyList);

        #endregion

        #region Properties

        /// <summary>
        /// true if agent is locked
        /// </summary>
        public bool IsLocked { get; private set; }

        public int KeyCount
        {
            get { return keyList.Count; }
        }

        public ConfirmUserPermissionDelegate ConfirmUserPermissionCallback { get; set; }

        public FilterKeyListDelegate FilterKeyListCallback { get; set; }

        #endregion

        #region Constructors

        protected Agent()
        {
            keyList = new List<ISshKey>();
        }

        #endregion

        #region Public Methods

        public void AddKey(ISshKey key)
        {
            if (IsLocked)
            {
                throw new AgentLockedException();
            }

            /* handle constraints */

            foreach (var constraint in key.Constraints)
            {
                if (
                    constraint.Type == KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM
                    && ConfirmUserPermissionCallback == null
                )
                {
                    // can't add key with confirm constraint if we don't have
                    // confirm callback
                    throw new InvalidOperationException(
                        "cannot add key with confirm constraint when there is no confirm callback"
                    );
                }

                if (constraint.Type == KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME)
                {
                    var lifetime = (uint)constraint.Data * 1000;
                    var timer = new Timer(lifetime);

                    var onTimerElapsed = default(ElapsedEventHandler);

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
            var matchingKey = keyList.TryGet(key.GetPublicKeyBlob());

            if (matchingKey != null)
            {
                RemoveKey(matchingKey);
            }

            keyList.Add(key);
            OnKeyAdded(key);
        }

        public void RemoveKey(ISshKey key)
        {
            if (IsLocked)
            {
                throw new AgentLockedException();
            }

            if (keyList.Remove(key))
            {
                OnKeyRemoved(key);
            }
        }

        public void RemoveAllKeys()
        {
            if (IsLocked)
            {
                throw new AgentLockedException();
            }

            var removeKeyList = ListKeys();

            foreach (var key in removeKeyList)
            {
                RemoveKey(key);
            }
        }

        public ICollection<ISshKey> ListKeys()
        {
            if (IsLocked)
            {
                return new List<ISshKey>();
            }

            return keyList.ToList();
        }

        public void Lock(byte[] aPassphrase)
        {
            if (IsLocked)
            {
                // can't lock if already locked
                throw new AgentLockedException();
            }

            lockedPassphrase = new SecureString();

            if (aPassphrase != null)
            {
                foreach (var b in aPassphrase)
                {
                    lockedPassphrase.AppendChar((char)b);
                }
            }

            IsLocked = true;
            OnLocked();
        }

        public void Unlock(byte[] aPassphrase)
        {
            if (!IsLocked)
            {
                // can't unlock if not locked
                throw new AgentLockedException();
            }

            if (aPassphrase == null)
            {
                aPassphrase = Array.Empty<byte>();
            }

            if (lockedPassphrase.Length != aPassphrase.Length)
            {
                // passwords definitely do not match
                throw new PassphraseException();
            }

            var lockedPassPtr = Marshal.SecureStringToGlobalAllocUnicode(lockedPassphrase);

            for (var i = 0; i < lockedPassphrase.Length; i++)
            {
                var lockedPassChar = Marshal.ReadInt16(lockedPassPtr, i * 2);

                if (lockedPassChar != aPassphrase[i])
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(lockedPassPtr);
                    throw new PassphraseException();
                }
            }

            Marshal.ZeroFreeGlobalAllocUnicode(lockedPassPtr);
            lockedPassphrase.Clear();
            IsLocked = false;
            OnLocked();
        }

        /// <summary>
        /// Answers the message.
        /// </summary>
        /// <param name='messageStream'>Message stream.</param>
        /// <param name="context">The connection context.</param>
        public void AnswerMessage(Stream messageStream, ConnectionContext context)
        {
            if (messageStream.CanTimeout)
            {
                messageStream.ReadTimeout = 5000;
            }

            var messageParser = new BlobParser(messageStream);
            var responseBuilder = new BlobBuilder();
            BlobHeader header;

            try
            {
                header = messageParser.ReadHeader();

                if (MessageReceived != null)
                {
                    var eventArgs = new MessageReceivedEventArgs(header);
                    MessageReceived(this, eventArgs);
                    if (eventArgs.Fail)
                    {
                        throw new Exception();
                    }
                }

                // There are some parts of the code below that rely on knowing the
                // position in the stream. So if a stream is not seekable, we need
                // to read the full length now to a copy in memory.
                if (!messageParser.BaseStream.CanSeek)
                {
                    // make copy of data from stream
                    var builder = new BlobBuilder();
                    builder.AddUInt32((uint)header.BlobLength);
                    builder.AddUInt8((byte)header.Message);
                    builder.AddBytes(messageParser.ReadBytes(header.BlobLength - 1));

                    // replace the parser with the in-memory stream
                    messageParser = new BlobParser(builder.GetBlob());

                    // ensure the parser is in the same position it was previously
                    messageParser.ReadHeader();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                header = new BlobHeader { Message = Message.UNKNOWN };
                // this will cause the switch statement below to use the default case
                // which returns an error to the stream.
            }

            switch (header.Message)
            {
                case Message.SSH2_AGENTC_REQUEST_IDENTITIES:
                    /*
                     * Reply with SSH2_AGENT_IDENTITIES_ANSWER.
                     */
                    try
                    {
                        var keyList = ListKeys()
                            .Where(
                                k => k.DestinationConstraint?.IdentityPermitted(context) ?? true
                            );

                        if (FilterKeyListCallback != null)
                        {
                            keyList = FilterKeyListCallback(keyList);
                        }

                        foreach (var key in keyList)
                        {
                            responseBuilder.AddBlob(key.GetPublicKeyBlob());
                            responseBuilder.AddStringBlob(key.Comment);
                        }

                        responseBuilder.InsertHeader(
                            Message.SSH2_AGENT_IDENTITIES_ANSWER,
                            keyList.Count()
                        );

                        // TODO may want to check that there is enough room in the message stream
                        break; // succeeded
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }

                    goto default; // failed

                case Message.SSH2_AGENTC_SIGN_REQUEST:
                    /*
                     * Reply with either SSH2_AGENT_SIGN_RESPONSE or SSH_AGENT_FAILURE,
                     * depending on whether we have that key or not.
                     */
                    try
                    {
                        var keyBlob = messageParser.ReadBlob();
                        var reqData = messageParser.ReadBlob();
                        var flags = new SignRequestFlags();
                        try
                        {
                            // usually, there are no flags, so parser will throw
                            flags = (SignRequestFlags)messageParser.ReadUInt32();
                        }
                        catch { }

                        // throws if key not found
                        var matchingKey = keyList.First(
                            key => key.GetPublicKeyBlob().SequenceEqual(keyBlob)
                        );

                        var user = default(string);
                        var forwardHostName = default(string);
                        var lastHostName = default(string);

                        if (matchingKey.DestinationConstraint?.Constraints.Any() ?? false)
                        {
                            if (!context.Sessions.Any())
                            {
                                throw new InvalidOperationException(
                                    "refusing use of destination constrained key to sign unbound connection"
                                );
                            }

                            ParseUserAuthRequest(
                                reqData,
                                matchingKey,
                                out user,
                                out var sessionId,
                                out var hostKey
                            );

                            if (
                                !matchingKey.DestinationConstraint.IdentityPermitted(
                                    context,
                                    user,
                                    out forwardHostName,
                                    out lastHostName
                                )
                            )
                            {
                                throw new InvalidOperationException();
                            }

                            if (!sessionId.SequenceEqual(context.Sessions.Last().SessionIdentifier))
                            {
                                throw new InvalidOperationException(
                                    $"unexpected session ID ({context.Sessions.Count()} listed) on signature request for target user {user} with key {matchingKey.GetSha256Fingerprint()}"
                                );
                            }

                            if (context.Sessions.Count() > 1 && hostKey == null)
                            {
                                throw new InvalidOperationException(
                                    "refusing use of destination-constrained key: mismatch between hostkey in request and most recently bound session"
                                );
                            }
                        }

                        var confirmConstraints = matchingKey.Constraints.Where(
                            constraint =>
                                constraint.Type == KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM
                        );

                        if (confirmConstraints.Any())
                        {
                            if (
                                !ConfirmUserPermissionCallback.Invoke(
                                    matchingKey,
                                    context.Process,
                                    user,
                                    forwardHostName,
                                    lastHostName
                                )
                            )
                            {
                                goto default;
                            }
                        }

                        /* create signature */
                        var signKey = matchingKey;
                        var signer = signKey.GetSigner(out var algName, flags);
                        signer.Init(true, signKey.GetPrivateKeyParameters());
                        signer.BlockUpdate(reqData, 0, reqData.Length);
                        var signature = signer.GenerateSignature();
                        signature = signKey.FormatSignature(signature);

                        var signatureBuilder = new BlobBuilder();
                        signatureBuilder.AddStringBlob(algName);
                        signatureBuilder.AddBlob(signature);
                        responseBuilder.AddBlob(signatureBuilder.GetBlob());
                        responseBuilder.InsertHeader(Message.SSH2_AGENT_SIGN_RESPONSE);

                        try
                        {
                            KeyUsed(this, new KeyUsedEventArgs(signKey, context.Process));
                        }
                        catch { }

                        break; // succeeded
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (FormatException)
                    {
                        // this is expected if the message had bad data
                    }
                    catch (InvalidOperationException)
                    {
                        // this is expected if there is not a matching key
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }

                    goto default; // failure

                case Message.SSH2_AGENTC_ADD_IDENTITY:
                case Message.SSH2_AGENTC_ADD_ID_CONSTRAINED:
                    /*
                     * Add to the list and return SSH_AGENT_SUCCESS, or
                     * SSH_AGENT_FAILURE if the key was malformed.
                     */

                    if (IsLocked)
                    {
                        goto default;
                    }

                    var constrained = header.Message == Message.SSH2_AGENTC_ADD_ID_CONSTRAINED;

                    try
                    {
                        var publicKeyParams = messageParser.ReadSsh2PublicKeyData(
                            out var nonce,
                            out var cert,
                            out var application
                        );
                        var privateKeyParams = messageParser.ReadSsh2KeyData(publicKeyParams);
                        var key = new SshKey(
                            publicKeyParams,
                            privateKeyParams,
                            "",
                            nonce,
                            cert,
                            application
                        )
                        {
                            Comment = messageParser.ReadString(),
                            Source = "External client"
                        };

                        if (constrained)
                        {
                            while (messageParser.BaseStream.Position < header.BlobLength + 4)
                            {
                                var constraint = new KeyConstraint
                                {
                                    Type = (KeyConstraintType)messageParser.ReadByte()
                                };

                                switch (constraint.Type)
                                {
                                    case KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM:
                                        // no extra data
                                        key.AddConstraint(constraint);
                                        break;
                                    case KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME:
                                        constraint.Data = messageParser.ReadUInt32();
                                        key.AddConstraint(constraint);
                                        break;
                                    case KeyConstraintType.SSH_AGENT_CONSTRAIN_EXTENSION:
                                        var extensionType = messageParser.ReadString();

                                        switch (extensionType)
                                        {
                                            case DestinationConstraint.ExtensionId:
                                                if (key.DestinationConstraint != null)
                                                {
                                                    throw new InvalidOperationException(
                                                        "can only have one destination constraint"
                                                    );
                                                }

                                                key.DestinationConstraint =
                                                    DestinationConstraint.Parse(
                                                        messageParser.ReadBlob()
                                                    );
                                                break;
                                            default:
                                                throw new NotSupportedException(
                                                    "unsupported constraint extension"
                                                );
                                        }
                                        break;
                                    default:
                                        throw new NotSupportedException(
                                            "unsupported constraint type"
                                        );
                                }
                            }
                        }

                        var matchingKey = ListKeys()
                            .FirstOrDefault(
                                k => k.GetPublicKeyBlob().SequenceEqual(key.GetPublicKeyBlob())
                            );

                        if (
                            matchingKey != null
                            && !(
                                matchingKey.DestinationConstraint?.IdentityPermitted(context)
                                ?? true
                            )
                        )
                        {
                            throw new InvalidOperationException(
                                "cannot replace destination constrained key"
                            );
                        }

                        AddKey(key);
                        responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);

                        break; // success!
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (InvalidOperationException)
                    {
                        // this is expected if there is not a constraint callback
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }

                    goto default; // failed

                case Message.SSH2_AGENTC_REMOVE_IDENTITY:
                    /*
                     * Remove from the list and return SSH_AGENT_SUCCESS, or
                     * perhaps SSH_AGENT_FAILURE if it wasn't in the list to
                     * start with.
                     */

                    if (IsLocked)
                    {
                        goto default;
                    }

                    var rKeyBlob = messageParser.ReadBlob();

                    try
                    {
                        var matchingKey = keyList.TryGet(rKeyBlob);

                        if (matchingKey == null)
                        {
                            throw new InvalidOperationException();
                        }

                        if (
                            !(matchingKey.DestinationConstraint?.IdentityPermitted(context) ?? true)
                        )
                        {
                            throw new InvalidOperationException();
                        }

                        var startKeyListLength = keyList.Count;

                        RemoveKey(matchingKey);

                        // only succeed if key was removed
                        if (keyList.Count == startKeyListLength - 1)
                        {
                            responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
                            break; //success!
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        // This is expected
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }
                    goto default; // failed

                case Message.SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
                    /*
                     * Remove all SSH-1 or SSH-2 keys.
                     */

                    if (IsLocked)
                    {
                        goto default;
                    }

                    try
                    {
                        RemoveAllKeys();
                        responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
                        break; //success!
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }
                    goto default; // failed

                case Message.SSH_AGENTC_LOCK:
                    try
                    {
                        Lock(messageParser.ReadBlob());

                        if (IsLocked)
                        {
                            responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
                            break;
                        }
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }
                    goto default;

                case Message.SSH_AGENTC_UNLOCK:
                    try
                    {
                        Unlock(messageParser.ReadBlob());

                        if (!IsLocked)
                        {
                            responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
                            break;
                        }
                    }
                    catch (AgentLockedException)
                    {
                        // This is expected
                    }
                    catch (PassphraseException)
                    {
                        // This is expected
                    }
                    catch (Exception ex)
                    {
                        Debug.Fail(ex.ToString());
                    }

                    goto default;

                case Message.SSH_AGENTC_EXTENSION:
                    try
                    {
                        var extensionType = messageParser.ReadString();

                        switch (extensionType)
                        {
                            case "session-bind@openssh.com":
                                var hostKey = messageParser.ReadBlob();
                                var sessionIdentifier = messageParser.ReadBlob();
                                var signature = messageParser.ReadBlob();
                                var isForwarding = messageParser.ReadBoolean();

                                context.AddSession(
                                    new SessionBind(
                                        new SshPublicKey(hostKey),
                                        sessionIdentifier,
                                        signature,
                                        isForwarding
                                    )
                                );

                                responseBuilder.InsertHeader(Message.SSH_AGENT_SUCCESS);
                                break;

                            default:
                                throw new NotSupportedException(
                                    $"unsupported extension: {extensionType}"
                                );
                        }

                        break;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(
                            $"unhandled exception in SSH_AGENTC_EXTENSION: ${ex.Message}"
                        );
                        Debugger.Break();
                    }

                    goto default;

                default:
                    responseBuilder.Clear();
                    responseBuilder.InsertHeader(Message.SSH_AGENT_FAILURE);
                    break;
            }

            // write response to stream
            if (messageStream.CanSeek)
            {
                messageStream.Position = 0;
            }

            messageStream.Write(responseBuilder.GetBlob(), 0, responseBuilder.Length);
            messageStream.Flush();
        }

        private void ParseUserAuthRequest(
            byte[] reqData,
            ISshKey key,
            out string user,
            out byte[] sessionId,
            out SshPublicKey hostKey
        )
        {
            hostKey = null;

            var userAuthParser = new BlobParser(reqData);

            sessionId = userAuthParser.ReadBlob();

            if (sessionId.Length == 0)
            {
                throw new FormatException();
            }

            var msg = userAuthParser.ReadByte();

            if (msg != SSH2_MSG_USERAUTH_REQUEST)
            {
                throw new FormatException();
            }

            user = userAuthParser.ReadString();

            var service = userAuthParser.ReadString();

            if (service != "ssh-connection")
            {
                throw new FormatException();
            }

            var method = userAuthParser.ReadString();
            var signatureFollows = userAuthParser.ReadBoolean();

            if (!signatureFollows)
            {
                throw new FormatException();
            }

            var algorithm = userAuthParser.ReadString();
            var mKeyBlob = userAuthParser.ReadBlob();

            var mKey = new SshPublicKey(mKeyBlob);

            if (!key.GetPublicKeyBlob().SequenceEqual(mKey.KeyBlob))
            {
                throw new FormatException();
            }

            if (algorithm != key.Algorithm.GetIdentifier())
            {
                throw new FormatException();
            }

            if (method == "publickey-hostbound-v00@openssh.com")
            {
                var hostKeyBlob = userAuthParser.ReadBlob();
                hostKey = new SshPublicKey(hostKeyBlob);
            }
            else if (method != "publickey")
            {
                throw new FormatException();
            }

            if (userAuthParser.BaseStream.Position != reqData.Length)
            {
                throw new FormatException();
            }
        }

        public abstract void Dispose();

        #endregion

        #region Private Methods

        private void OnKeyAdded(ISshKey key)
        {
            KeyAdded?.Invoke(this, new SshKeyEventArgs(key));
        }

        private void OnKeyRemoved(ISshKey key)
        {
            KeyRemoved?.Invoke(this, new SshKeyEventArgs(key));
        }

        /// <summary>
        /// Fires lock event for listeners
        /// </summary>
        private void OnLocked()
        {
            Locked?.Invoke(this, new LockEventArgs(IsLocked));
        }

        #endregion
    }
}
