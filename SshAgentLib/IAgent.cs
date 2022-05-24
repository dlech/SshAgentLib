//
// IAgent.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2014,2022 David Lechner
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
using System.IO;
using System.Linq;
using SshAgentLib.Keys;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Common interface of Agent and AgentClient
    /// </summary>
    public interface IAgent
    {
        event SshKeyEventHandler KeyAdded;

        event SshKeyEventHandler KeyRemoved;

        void AddKey(ISshKey key);

        void RemoveKey(ISshKey key);

        void RemoveAllKeys(SshVersion version);

        ICollection<ISshKey> ListKeys(SshVersion version);

        void Lock(byte[] passphrase);

        void Unlock(byte[] passphrase);
    }

    public static class IAgentExt
    {
        /// <summary>
        /// Reads file and loads key into agent
        /// </summary>
        /// <param name="agent">the agent</param>
        /// <param name="fileName">pathname of file to read</param>
        /// <param name="getPassPhraseCallback">method that returns passphrase</param>
        /// <param name="constraints">additional constraints</param>
        /// <param name="progress">Optional progress callback.</param>
        /// <exception cref="AgentFailureException">
        /// Agent returned SSH_AGENT_FAILURE
        /// </exception>
        /// <exception cref="UnauthorizedAccessException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="PathTooLongException"></exception>
        /// <exception cref="DirectoryNotFoundException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        /// <exception cref="NotSupportedException"></exception>
        /// <returns>The ssh key that was read from the file</returns>
        public static ISshKey AddKeyFromFile(
            this IAgent agent,
            string fileName,
            SshPrivateKey.GetPassphraseFunc getPassPhraseCallback,
            ICollection<Agent.KeyConstraint> constraints = null,
            IProgress<double> progress = null
        )
        {
            var publicKey = default(SshPublicKey);

            try
            {
                publicKey = SshPublicKey.Read(File.OpenRead($"{fileName}.pub"));
            }
            catch
            {
                // silently ignore, SshPrivateKey.Read() will raise proper
                // error if this file was required.
            }

            var privateKey = SshPrivateKey.Read(File.OpenRead(fileName), publicKey);

            try
            {
                publicKey = SshPublicKey.Read(File.OpenRead($"{fileName}-cert.pub"));
            }
            catch
            {
                // silently ignore, this file is optional
            }

            var key = new SshKey(
                privateKey.PublicKey.Version,
                privateKey.PublicKey.Parameter,
                privateKey.Decrypt(getPassPhraseCallback, progress),
                privateKey.PublicKey.Comment,
                publicKey.Nonce,
                publicKey.Certificate,
                publicKey.Application
            );

            if (constraints != null)
            {
                foreach (var constraint in constraints)
                {
                    key.AddConstraint(constraint);
                }
            }

            // prevent error in Pageant by attempting to remove key before adding it
            // this makes behavior more consistent with OpenSSH
            if (agent is PageantClient)
            {
                try
                {
                    agent.RemoveKey(key);
                }
                catch (Exception)
                { /* error will occur if key is not loaded */
                }
            }

            agent.AddKey(key);

            return key;
        }

        public static void RemoveAllKeys(this IAgent agent)
        {
            foreach (SshVersion version in Enum.GetValues(typeof(SshVersion)))
            {
                agent.RemoveAllKeys(version);
            }
        }

        public static ICollection<ISshKey> GetAllKeys(this IAgent agent)
        {
            var allKeysList = new List<ISshKey>();

            foreach (SshVersion version in Enum.GetValues(typeof(SshVersion)))
            {
                try
                {
                    var versionList = agent.ListKeys(version);
                    allKeysList.AddRange(versionList);
                }
                catch (Exception) { }
                // TODO something better with exceptions
            }

            return allKeysList;
        }

        /// <summary>
        /// Checks if a matching key is loaded in the agent.
        /// </summary>
        /// <param name="agent">The agent.</param>
        /// <param name="key">The key to match against.</param>
        /// <returns>
        /// <c>true</c> if a matching key was found, otherwise <c>false</c>
        /// </returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool Contains(this IAgent agent, SshPublicKey key)
        {
            if (agent == null)
            {
                throw new ArgumentNullException(nameof(agent));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return agent.ListKeys(key.Version).Any(k => key.Matches(k.GetPublicKeyBlob()));
        }
    }
}
