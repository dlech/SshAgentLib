// SPDX-License-Identifier: MIT
// Copyright (c) 2017,2022 David Lechner <david@lechnology.com>

using System;
using System.Collections.Generic;
using System.Linq;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// Openssh certificate info.
    /// </summary>
    /// <remarks>
    /// This contains the common OpenSSH certificate info described in
    /// https://api.libssh.org/rfc/PROTOCOL.certkeys in deserialized form.
    ///
    /// Essentially, this is all of the fields except for the nonce and the
    /// public key parameters.
    /// </remarks>
    public sealed class OpensshCertificateInfo
    {
        public OpensshCertType Type { get; }
        public ulong Serial { get; }
        public string KeyId { get; }
        public IList<string> Principals { get; }
        public DateTime ValidAfter { get; }
        public DateTime ValidBefore { get; }
        public byte[] CriticalOptions { get; }
        public byte[] Extensions { get; }
        public byte[] Reserved { get; }
        public SshPublicKey SignatureKey { get; }
        public byte[] Signature { get; }

        public OpensshCertificateInfo(
            OpensshCertType type,
            ulong serial,
            string keyId,
            IEnumerable<string> principals,
            DateTime validAfter,
            DateTime validBefore,
            byte[] critical,
            byte[] extensions,
            byte[] reserved,
            SshPublicKey signatureKey,
            byte[] signature
        )
        {
            if (principals == null)
            {
                throw new ArgumentNullException(nameof(principals));
            }

            Type = type;
            Serial = serial;
            KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
            Principals = principals.ToList().AsReadOnly();
            ValidAfter = validAfter;
            ValidBefore = validBefore;
            CriticalOptions = critical;
            Extensions = extensions;
            Reserved = reserved;
            SignatureKey = signatureKey ?? throw new ArgumentNullException(nameof(signatureKey));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        }
    }

    public enum OpensshCertType
    {
        User = 1,
        Host = 2,
    }
}
