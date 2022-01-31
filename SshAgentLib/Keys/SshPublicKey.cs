// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using dlech.SshAgentLib;
using Org.BouncyCastle.Crypto;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// An SSH public key.
    /// </summary>
    public sealed class SshPublicKey
    {
        /// <summary>
        /// The SSH protocol version.
        /// </summary>
        public SshVersion Version { get; }

        /// <summary>
        /// The encryption parameter.
        /// </summary>
        public AsymmetricKeyParameter Parameter { get; }

        /// <summary>
        /// Optional comment.
        /// </summary>
        public string Comment { get; }

        /// <summary>
        /// Optional certificate.
        /// </summary>
        public object Certificate { get; }

        /// <summary>
        /// Creates a new public key.
        /// </summary>
        /// <param name="version">The SSH version.</param>
        /// <param name="parameter">The encryption parameter.</param>
        /// <param name="comment">Optional comment.</param>
        /// <param name="certificate">Optional certificate.</param>
        public SshPublicKey(
            SshVersion version,
            AsymmetricKeyParameter parameter,
            string comment = null,
            object certificate = null
        )
        {
            Version = version;
            Parameter = parameter;
            Comment = comment;
            Certificate = certificate;
        }

        /// <summary>
        /// Returns a copy of the key with a new comment.
        /// </summary>
        /// <param name="comment">The new comment.</param>
        /// <returns>A new key.</returns>
        public SshPublicKey WithComment(string comment)
        {
            return new SshPublicKey(Version, Parameter, comment, Certificate);
        }

        /// <summary>
        /// Returns a copy of the key with a new certificate.
        /// </summary>
        /// <param name="certificate">The new certificate.</param>
        /// <returns>The new key.</returns>
        public SshPublicKey WithCertificate(object certificate)
        {
            return new SshPublicKey(Version, Parameter, Comment, certificate);
        }
    }
}
