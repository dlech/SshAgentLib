// SPDX-License-Identifier: MIT
// Copyright (c) 2017,2022 David Lechner <david@lechnology.com>

using System;
using System.Collections.Generic;
using System.Linq;
using SshAgentLib.Keys;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Openssh certificate.
    /// </summary>
    public sealed class OpensshCertificate
    {
        public Ssh2CertType Type { get; }
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

        public OpensshCertificate(
            Ssh2CertType type,
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

    public enum Ssh2CertType
    {
        User = 1,
        Host = 2,
    }
}
