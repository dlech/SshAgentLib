//
// IAgent.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2014 David Lechner
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

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Common interface of Agent and AgentClient
    /// </summary>
    public interface IAgent
    {
        event SshKeyEventHandler KeyAdded;

        event SshKeyEventHandler KeyRemoved;

        void AddKey(ISshKey aKey);

        void RemoveKey(ISshKey aKey);

        void RemoveAllKeys(SshVersion aVersion);

        ICollection<ISshKey> ListKeys(SshVersion aVersion);

        void Lock(byte[] aPassphrase);

        void Unlock(byte[] aPassphrase);
    }

    public static class IAgentExt
    {
        /// <summary>
        /// Reads file and loads key into agent
        /// </summary>
        /// <param name="aAgent">the agent</param>
        /// <param name="aFileName">pathname of file to read</param>
        /// <param name="aGetPassPhraseCallback">method that returns passphrase</param>
        /// <param name="aConstraints">additional constraints</param>
        /// <exception cref="AgentFailureException">
        /// Agent returned SSH_AGENT_FAILURE
        /// </exception>
        /// <exception cref="KeyFormatterException">
        /// File format was not recognized
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
            this IAgent aAgent,
            string aFileName,
            KeyFormatter.GetPassphraseCallback aGetPassPhraseCallback,
            ICollection<Agent.KeyConstraint> aConstraints = null
        )
        {
            string firstLine;
            using (var fileReader = File.OpenText(aFileName))
            {
                firstLine = fileReader.ReadLine();
            }
            var formatter = KeyFormatter.GetFormatter(firstLine);
            formatter.GetPassphraseCallbackMethod = aGetPassPhraseCallback;
            var key = formatter.DeserializeFile(aFileName);
            if (aConstraints != null)
            {
                foreach (var constraint in aConstraints)
                {
                    key.AddConstraint(constraint);
                }
            }
            // prevent error in Pageant by attempting to remove key before adding it
            // this makes behavior more consistent with OpenSSH
            if (aAgent is PageantClient)
            {
                try
                {
                    aAgent.RemoveKey(key);
                }
                catch (Exception)
                { /* error will occur if key is not loaded */
                }
            }
            aAgent.AddKey(key);
            return key;
        }

        public static void RemoveAllKeys(this IAgent aAgent)
        {
            foreach (SshVersion version in Enum.GetValues(typeof(SshVersion)))
            {
                aAgent.RemoveAllKeys(version);
            }
        }

        public static ICollection<ISshKey> GetAllKeys(this IAgent aAgent)
        {
            List<ISshKey> allKeysList = new List<ISshKey>();
            foreach (SshVersion version in Enum.GetValues(typeof(SshVersion)))
            {
                try
                {
                    var versionList = aAgent.ListKeys(version);
                    allKeysList.AddRange(versionList);
                }
                catch (Exception) { }
                // TODO something better with exceptions
            }
            return allKeysList;
        }
    }
}
