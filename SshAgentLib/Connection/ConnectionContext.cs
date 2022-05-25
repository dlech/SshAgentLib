// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using SshAgentLib.Extension;

namespace SshAgentLib.Connection
{
    /// <summary>
    /// Class for maintaining the state of a connection to an SSH agent.
    /// </summary>
    public sealed class ConnectionContext
    {
        private readonly List<SessionBind> sessions = new List<SessionBind>();

        /// <summary>
        /// Gets and sets the bound session information if this connection has
        /// been bound or <c>null</c> if the session has not been bound.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Thrown if trying to set a new non-null value when the context has
        /// has already been bound to a session.
        /// </exception>
        public IEnumerable<SessionBind> Sessions => sessions;

        /// <summary>
        /// Gets the processes on the other end of the connection. This may be
        /// <c>null</c> if it is not technically possible to get the process.
        /// </summary>
        public Process Process { get; }

        /// <summary>
        /// Creates a new connection context.
        /// </summary>
        /// <param name="process">
        /// The process on the other end of the connection.
        /// </param>
        public ConnectionContext(Process process = null)
        {
            Process = process;
        }

        public void AddSession(SessionBind session)
        {
            if (sessions.Any(s => s.Matches(session)))
            {
                throw new InvalidOperationException(
                    "a session with this id has already been added"
                );
            }

            sessions.Add(session);
        }
    }
}
