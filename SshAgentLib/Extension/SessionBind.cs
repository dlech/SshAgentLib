// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.Linq;
using SshAgentLib.Keys;

namespace SshAgentLib.Extension
{
    /// <summary>
    /// Data structure to encapsulate session binding info received over the wire.
    /// </summary>
    public class SessionBind
    {
        /// <summary>
        /// This host public key associated with this session.
        /// </summary>
        public SshPublicKey HostKey { get; }

        /// <summary>
        /// A unique session identifier.
        /// </summary>
        internal byte[] SessionIdentifier { get; }

        /// <summary>
        /// A signature over the session identifier signed by the host.
        /// </summary>
        internal byte[] Signature { get; }

        /// <summary>
        /// Indicates if this session is forwards the SSH agent.
        /// </summary>
        public bool IsForwarding { get; }

        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="hostKey">The host public key.</param>
        /// <param name="sessionIdentifier">The session identifier.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="isForwarding">The forwarding flag.</param>
        /// <exception cref="ArgumentNullException">
        /// Thrown if any arguments are null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if the signature is not valid for the given host key and session identifier.
        /// </exception>
        public SessionBind(
            SshPublicKey hostKey,
            byte[] sessionIdentifier,
            byte[] signature,
            bool isForwarding
        )
        {
            HostKey = hostKey ?? throw new ArgumentNullException(nameof(hostKey));
            SessionIdentifier =
                sessionIdentifier ?? throw new ArgumentNullException(nameof(sessionIdentifier));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            IsForwarding = isForwarding;

            if (!hostKey.VerifySignature(signature, sessionIdentifier))
            {
                throw new ArgumentException("invalid signature", nameof(signature));
            }
        }

        /// <summary>
        /// Tests if two session bindings have the same session identifier.
        /// </summary>
        /// <param name="other">
        /// The other session binding instance.
        /// </param>
        /// <returns>
        /// <c>true</c> if the session identifiers are the same, otherwise <c>false<c/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if any arguments are null.
        /// </exception>
        public bool Matches(SessionBind other)
        {
            if (other == null)
            {
                throw new ArgumentNullException(nameof(other));
            }

            return SessionIdentifier.SequenceEqual(other.SessionIdentifier);
        }
    }
}
