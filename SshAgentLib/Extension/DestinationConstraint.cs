// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

// https://github.com/openssh/openssh-portable/blob/56a0697fe079ff3e1ba30a2d5c26b5e45f7b71f8/PROTOCOL.agent

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using dlech.SshAgentLib;
using SshAgentLib.Connection;
using SshAgentLib.Keys;

namespace SshAgentLib.Extension
{
    public sealed class DestinationConstraint
    {
        /// <summary>
        /// The extension constraint identifier for this constraint type.
        /// </summary>
        public const string ExtensionId = "restrict-destination-v00@openssh.com";

        public IReadOnlyCollection<Constraint> Constraints { get; }

        public sealed class KeySpec
        {
            public SshPublicKey HostKey { get; }
            public bool IsCertificateAuthority { get; }

            public KeySpec(SshPublicKey hostKey, bool isCertificateAuthority)
            {
                HostKey = hostKey ?? throw new ArgumentNullException(nameof(hostKey));
                IsCertificateAuthority = isCertificateAuthority;
            }
        }

        public sealed class Hop
        {
            public string UserName { get; }
            public string HostName { get; }
            public IReadOnlyCollection<KeySpec> HostKeys { get; }

            public Hop(string userName, string hostName, IReadOnlyCollection<KeySpec> hostKeys)
            {
                UserName = userName;
                HostName = hostName;
                HostKeys = hostKeys ?? throw new ArgumentNullException(nameof(hostKeys));
            }

            internal static Hop Parse(byte[] fromBlob)
            {
                var parser = new BlobParser(fromBlob);

                var userName = parser.ReadString();
                var hostName = parser.ReadString();
                var extensions = parser.ReadBlob();

                if (extensions.Length != 0)
                {
                    throw new NotSupportedException("unsupported extensions");
                }

                if (userName == string.Empty)
                {
                    userName = null;
                }

                if (hostName == string.Empty)
                {
                    hostName = null;
                }

                var list = new List<KeySpec>();

                while (parser.BaseStream.Position < fromBlob.Length)
                {
                    var keyBlob = parser.ReadBlob();
                    var isCa = parser.ReadBoolean();

                    list.Add(new KeySpec(new SshPublicKey(keyBlob), isCa));
                }

                return new Hop(userName, hostName, list);
            }

            internal byte[] ToBlob()
            {
                var builder = new BlobBuilder();

                builder.AddStringBlob(UserName ?? "");
                builder.AddStringBlob(HostName ?? "");
                builder.AddBlob(Array.Empty<byte>()); // extensions

                foreach (var k in HostKeys)
                {
                    builder.AddBlob(k.HostKey.KeyBlob);
                    builder.AddBoolean(k.IsCertificateAuthority);
                }

                return builder.GetBlob();
            }
        }

        public sealed class Constraint
        {
            public Hop From { get; }
            public Hop To { get; }

            public Constraint(Hop from, Hop to)
            {
                From = from ?? throw new ArgumentNullException(nameof(from));
                To = to ?? throw new ArgumentNullException(nameof(to));

                if (!string.IsNullOrWhiteSpace(from.UserName))
                {
                    throw new ArgumentException("from user name must be empty", nameof(from));
                }

                if (string.IsNullOrWhiteSpace(to.HostName))
                {
                    throw new ArgumentException("to host name is required", nameof(to));
                }

                if (to.HostKeys.Count == 0)
                {
                    throw new ArgumentException("at least one to host key is required", nameof(to));
                }
            }

            public override string ToString()
            {
                var fromUser = From.UserName == null ? "" : $"{From.UserName}@";
                var fromHost = From.HostName ?? "(ORIGIN)";
                var fromKeys = $"({From.HostKeys.Count} keys)";

                var toUser = To.UserName == null ? "" : $"{To.UserName}@";
                var toHost = To.HostName ?? "(ANY)";
                var toKeys = $"({To.HostKeys.Count} keys)";

                return $"constraint {fromUser}{fromHost} {fromKeys} > {toUser}{toHost} {toKeys})";
            }

            internal static Constraint Parse(byte[] blob)
            {
                if (blob == null)
                {
                    throw new ArgumentNullException(nameof(blob));
                }
                var parser = new BlobParser(blob);

                var fromBlob = parser.ReadBlob();
                var toBlob = parser.ReadBlob();
                var extensionsBlob = parser.ReadBlob();

                if (extensionsBlob.Length != 0)
                {
                    throw new NotSupportedException("unsupported extensions");
                }

                return new Constraint(Hop.Parse(fromBlob), Hop.Parse(toBlob));
            }

            internal byte[] ToBlob()
            {
                var builder = new BlobBuilder();

                builder.AddBlob(From.ToBlob());
                builder.AddBlob(To.ToBlob());
                builder.AddBlob(Array.Empty<byte>()); // extensions

                return builder.GetBlob();
            }
        }

        /// <summary>
        /// Converts the constraint to the over-the-wire binary format.
        /// </summary>
        /// <returns>A new binary blob.</returns>
        public byte[] ToBlob()
        {
            var builder = new BlobBuilder();

            foreach (var c in Constraints)
            {
                builder.AddBlob(c.ToBlob());
            }

            return builder.GetBlob();
        }

        internal bool IdentityPermitted(ConnectionContext context)
        {
            return IdentityPermitted(context, null, out var forwardHostName, out var lastHostName);
        }

        internal bool IdentityPermitted(
            ConnectionContext context,
            string user,
            out string forwardHostName,
            out string lastHostName
        )
        {
            forwardHostName = null;
            lastHostName = null;

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // if there are no constraints, this ok to use key
            if (Constraints.Count == 0)
            {
                return true;
            }

            // this constraint requires a bound session, so if there is not
            // one, don't allow use of the key
            if (!context.Sessions.Any())
            {
                return true;
            }

            var fromKey = default(SshPublicKey);

            foreach (var s in context.Sessions)
            {
                Debug.WriteLine(
                    $"from hostkey {(fromKey == null ? "(ORIGIN)" : fromKey.Sha256Fingerprint)} to user {user ?? "(ANY)"} hostkey {s.HostKey.Sha256Fingerprint}"
                );

                var testUser = default(string);

                if (s == context.Sessions.Last())
                {
                    testUser = user;

                    if (s.IsForwarding && user != null)
                    {
                        Debug.WriteLine("tried to sign on forwarding hop");
                        return false;
                    }
                }
                else if (!s.IsForwarding)
                {
                    Debug.WriteLine("tried to sign through signing bind");
                    return false;
                }

                if (!PermittedByConstraints(fromKey, s.HostKey, testUser, out var hostName))
                {
                    return false;
                }

                if (s == context.Sessions.First())
                {
                    forwardHostName = hostName;
                }
                else if (s == context.Sessions.Last())
                {
                    lastHostName = hostName;
                }

                fromKey = s.HostKey;
            }

            return true;
        }

        private bool PermittedByConstraints(
            SshPublicKey fromKey,
            SshPublicKey toKey,
            string user,
            out string hostName
        )
        {
            hostName = null;

            foreach (var c in Constraints)
            {
                if (fromKey == null)
                {
                    // We are matching the first hop
                    if (c.From.HostName != null || c.From.HostKeys.Count > 0)
                    {
                        continue;
                    }
                }
                else if (!MatchKeyHop("from", fromKey, c.From))
                {
                    continue;
                }

                if (toKey != null && !MatchKeyHop("to", toKey, c.To))
                {
                    continue;
                }

                if (user != null && c.To.UserName != null && !MatchPattern(user, c.To.UserName))
                {
                    continue;
                }

                if (hostName != null)
                {
                    hostName = c.To.HostName;
                }

                Debug.WriteLine($"allowed for hostname {c.To.HostName ?? "*"}");

                return true;
            }

            return false;
        }

        private static bool MatchKeyHop(string tag, SshPublicKey key, Hop dest)
        {
            var hostname = dest.HostName ?? "(ORIGIN)";

            if (key == null)
            {
                return false;
            }

            Debug.WriteLine(
                $"{tag}: entering hostname {hostname}, requested key {key.Sha256Fingerprint}, {dest.HostKeys.Count} available"
            );

            foreach (var k in dest.HostKeys)
            {
                if (k == null)
                {
                    return false;
                }

                Debug.WriteLine(
                    $"{tag}: key: {(k.IsCertificateAuthority ? "CA" : "")} {k.HostKey.Sha256Fingerprint}"
                );

                if (key.Certificate == null)
                {
                    if (k.IsCertificateAuthority || !key.Matches(k.HostKey))
                    {
                        continue;
                    }

                    return true;
                }

                if (!k.IsCertificateAuthority)
                {
                    continue;
                }

                if (!key.Certificate.SignatureKey.Matches(k.HostKey))
                {
                    continue;
                }

                // TODO: check that certificate is valid
                // if (!CertCheckHost(key, hostname, 1, algos, out var reason))
                // {
                //     Debug.WriteLine(
                //         $"cert {key.Certificate.KeyId} / hostname {hostname} rejected: {reason}"
                //     );
                // }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Compares the string against a given pattern.
        /// </summary>
        /// <param name="str">The string.</param>
        /// <param name="pattern">The pattern to match, where "*" means any sequence of characters, and "?" means any single character.</param>
        /// <returns><c>true</c> if the string matches the given pattern; otherwise <c>false</c>.</returns>
        public static bool MatchPattern(string str, string pattern)
        {
            return new Regex(
                $"^{Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".")}$"
            ).IsMatch(str);
        }

        public DestinationConstraint(IReadOnlyCollection<Constraint> constraints)
        {
            Constraints = constraints ?? throw new ArgumentNullException(nameof(constraints));
        }

        /// <summary>
        /// Parses binary data for encoded destination constraint information.
        /// </summary>
        /// <param name="blob">The binary data.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">
        /// Throws in <paramref name="blob"/> is <c>null</c>.
        /// </exception>
        public static DestinationConstraint Parse(byte[] blob)
        {
            if (blob == null)
            {
                throw new ArgumentNullException(nameof(blob));
            }

            var parser = new BlobParser(blob);
            var list = new List<Constraint>();

            while (parser.BaseStream.Position < blob.Length)
            {
                var constraintBlob = parser.ReadBlob();

                list.Add(Constraint.Parse(constraintBlob));
            }

            return new DestinationConstraint(list);
        }
    }
}
