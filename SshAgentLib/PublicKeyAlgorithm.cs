//
// PublicKeyAlgorithm.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012,2015,2017,2022 David Lechner
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
using System.Reflection;
using SshAgentLib;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Public Key Algorithms supports by SSH
    /// </summary>
    public enum PublicKeyAlgorithm
    {
        [KeyFormatIdentifier("ssh-rsa")]
        SshRsa,

        [KeyFormatIdentifier("ssh-rsa-cert-v01@openssh.com")]
        SshRsaCertV1,

        [KeyFormatIdentifier("ssh-dss")]
        SshDss,

        [KeyFormatIdentifier("ssh-dss-cert-v01@openssh.com")]
        SshDssCertV1,

        [KeyFormatIdentifier("ecdsa-sha2-nistp256")]
        EcdsaSha2Nistp256,

        [KeyFormatIdentifier("ecdsa-sha2-nistp256-cert-v01@openssh.com")]
        EcdsaSha2Nistp256CertV1,

        [KeyFormatIdentifier("ecdsa-sha2-nistp384")]
        EcdsaSha2Nistp384,

        [KeyFormatIdentifier("ecdsa-sha2-nistp384-cert-v01@openssh.com")]
        EcdsaSha2Nistp384CertV1,

        [KeyFormatIdentifier("ecdsa-sha2-nistp521")]
        EcdsaSha2Nistp521,

        [KeyFormatIdentifier("ecdsa-sha2-nistp521-cert-v01@openssh.com")]
        EcdsaSha2Nistp521CertV1,

        [KeyFormatIdentifier("ssh-ed25519")]
        SshEd25519,

        [KeyFormatIdentifier("ssh-ed25519-cert-v01@openssh.com")]
        SshEd25519CertV1,

        [KeyFormatIdentifier("ssh-ed448")]
        SshEd448,

        [KeyFormatIdentifier("ssh-ed448-cert-v01@openssh.com")]
        SshEd448CertV1,
    }

    public static class PublicKeyAlgorithmExt
    {
        /// <summary>
        /// Gets the identifier string for the key algorithm.
        /// </summary>
        public static string GetIdentifier(this PublicKeyAlgorithm algo)
        {
            var type = algo.GetType();

            return type.GetField(Enum.GetName(type, algo))
                .GetCustomAttribute<KeyFormatIdentifierAttribute>()
                .Identifier;
        }

        /// <summary>
        /// Gets the elliptic curve domain identifier string for the key algorithm.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// Thrown if the algorithm is not an elliptic curve algorithm.
        /// </exception>
        public static string GetCurveDomainIdentifier(this PublicKeyAlgorithm algo)
        {
            var id = algo.GetIdentifier();

            if (!id.StartsWith("ecdsa-sha2-", StringComparison.Ordinal))
            {
                throw new ArgumentException("requires elliptic curve algorithm");
            }

            return id.Replace("ecdsa-sha2-", string.Empty)
                .Replace("-cert-v01@openssh.com", string.Empty);
        }
    }
}
