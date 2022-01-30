//
// OpensshCertificate.cs
//
// Copyright (c) 2017 David Lechner
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
using System.Linq;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Openssh certificate.
    /// </summary>
    /// <remarks>
    /// Based on <c>struct sshkey_cert</c> in sshkey.h.
    /// </remarks>
    public sealed class OpensshCertificate
    {
        public byte[] Blob { get; private set; }
        public Ssh2CertType Type { get; private set; }
        public ulong Serial { get; private set; }
        public string KeyId { get; private set; }
        public IList<string> Principals { get; private set; }
        public DateTime ValidAfter { get; private set; }
        public DateTime ValidBefore { get; private set; }
        public object Critical { get; private set; }
        public object Extenstions { get; private set; }
        public object SignatureKey { get; private set; }

        public OpensshCertificate(
            byte[] blob,
            Ssh2CertType type,
            ulong serial,
            string keyId,
            IEnumerable<string> principals,
            DateTime validAfter,
            DateTime validBefore,
            object critical,
            object extensions,
            object signatureKey
        )
        {
            Blob = blob;
            Type = type;
            Serial = serial;
            KeyId = keyId;
            if (principals == null)
            {
                Principals = new List<string>().AsReadOnly();
            }
            else
            {
                Principals = principals.ToList().AsReadOnly();
            }
            ValidAfter = validAfter;
            ValidBefore = validBefore;
            Critical = critical;
            Extenstions = extensions;
            SignatureKey = signatureKey;
        }
    }

    public enum Ssh2CertType
    {
        User = 1,
        Host = 2,
    }
}
