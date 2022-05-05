// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using dlech.SshAgentLib;

namespace SshAgentLib.Keys
{
    /// <summary>
    /// RFC 4716 SSH public key.
    /// </summary>
    /// <remarks>
    /// This is the public key format exported by PuTTGen.
    /// </remarks>
    /// <seealso cref="https://datatracker.ietf.org/doc/html/rfc4716"/>
    public static class Rfc4716PublicKey
    {
        /// <summary>
        /// RFC specified first line of file.
        /// </summary>
        public const string FirstLine = "---- BEGIN SSH2 PUBLIC KEY ----";

        /// <summary>
        /// RFC specified last line of file.
        /// </summary>
        private const string lastLine = "---- END SSH2 PUBLIC KEY ----";

        /// <summary>
        /// RFC specified subject header key.
        /// </summary>
        [SuppressMessage(
            "CodeQuality",
            "IDE0051:Remove unused private members",
            Justification = "future use"
        )]
        private const string subjectHeader = "subject";

        /// <summary>
        /// RFC specified comment header key.
        /// </summary>
        private const string commentHeader = "comment";

        /// <summary>
        /// RFC specified custom header prefix.
        /// </summary>
        [SuppressMessage(
            "CodeQuality",
            "IDE0051:Remove unused private members",
            Justification = "future use"
        )]
        private const string privateHeaderPrefix = "x-";

        /// <summary>
        /// Regex to match line "header: value" with optional trailing backslash.
        /// </summary>
        /// <remarks>
        /// Header is group 1, value is group 2 and trailing backslash is group 3.
        /// </remarks>
        private static readonly Regex headerRegex = new Regex("^([^:]+):\\s*(.*?)(\\\\?)$");

        /// <summary>
        /// Reads a RFC 4716 public key.
        /// </summary>
        /// <param name="stream">
        /// A stream containing the key data.
        /// </param>
        /// <returns>
        /// A new public key object.
        /// </returns>
        /// <exception cref="SshKeyFileFormatException"></exception>
        public static SshPublicKey Read(Stream stream)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using (var reader = new StreamReader(stream))
            {
                var line = reader.ReadLine();

                if (line != FirstLine)
                {
                    throw new SshKeyFileFormatException($"First line must be {FirstLine}");
                }

                var headers = new Dictionary<string, string>();

                for (; ; )
                {
                    line = reader.ReadLine();

                    var match = headerRegex.Match(line);

                    if (!match.Success)
                    {
                        break;
                    }

                    // RFC says header keys are case insensitive ASCII values so normalize to lower case.
                    var key = match.Groups[1].Value.ToLowerInvariant();
                    var value = new StringBuilder(match.Groups[2].Value);
                    var continuation = match.Groups[3].Value;

                    // header values can be continued on the next line if the last character is a backslash
                    while (continuation == "\\")
                    {
                        line = reader.ReadLine();

                        match = Regex.Match(line, "^(.*?)(\\\\?)$");

                        // this match should never fail
                        if (!match.Success)
                        {
                            throw new SshKeyFileFormatException("unexpected regex match failure");
                        }

                        value.Append(match.Groups[1].Value);
                        continuation = match.Groups[2].Value;
                    }

                    // if value is quoted, trim the quotes
                    if (value[0] == '"' && value[value.Length - 1] == '"')
                    {
                        value.Remove(0, 1);
                        value.Remove(value.Length - 1, 1);
                    }

                    headers.Add(key, value.ToString());
                }

                // the remaining lines of the file are the key in base64 format
                var base64Key = new StringBuilder();

                while (line != lastLine)
                {
                    base64Key.Append(line);
                    line = reader.ReadLine();
                }

                var keyData = Convert.FromBase64String(base64Key.ToString());

                // comment is only header currently used
                headers.TryGetValue(commentHeader, out var comment);

                return new SshPublicKey(SshVersion.SSH2, keyData, comment);
            }
        }
    }
}
