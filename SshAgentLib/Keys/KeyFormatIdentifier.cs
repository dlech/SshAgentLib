// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;

using dlech.SshAgentLib;

namespace SshAgentLib
{
    public static class KeyFormatIdentifier
    {
        /// <summary>
        /// Parses an ssh key type identifier string.
        /// </summary>
        /// <param name="identifier">The string to parse.</param>
        /// <returns>The public key algorithm specified by <paramref name="identifier"/></returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="identifier"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="identifier"/> is not a supported algorithm.
        /// </exception>
        public static PublicKeyAlgorithm Parse(string identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            foreach (PublicKeyAlgorithm member in Enum.GetValues(typeof(PublicKeyAlgorithm)))
            {
                if (identifier == member.GetIdentifier())
                {
                    return member;
                }
            }

            throw new ArgumentException(
                $"unsupported identifier '{identifier}'",
                nameof(identifier)
            );
        }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class KeyFormatIdentifierAttribute : Attribute
    {
        /// <summary>
        /// Attribute applied to <see cref="PublicKeyAlgorithm"/> members to map identifier strings.
        /// </summary>
        /// <param name="identifier">The identifier string.</param>
        public KeyFormatIdentifierAttribute(string identifier)
        {
            Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
        }

        public string Identifier { get; }
    }
}
