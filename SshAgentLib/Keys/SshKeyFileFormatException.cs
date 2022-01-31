// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// Exception that indicates that an SSH key file was not properly formatted
    /// and could not be fully parsed.
    /// </summary>
    public sealed class SshKeyFileFormatException : Exception
    {
        /// <summary>
        /// Creates a new exception.
        /// </summary>
        /// <param name="message">The exception message.</param>
        public SshKeyFileFormatException(string message) : base(message) { }
    }
}
