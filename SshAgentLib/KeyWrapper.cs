// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2014,2022 David Lechner <david@lechnology.com>

namespace dlech.SshAgentLib
{
    /// <summary>
    /// Wrapper around <see cref="ISshKey"/> for WinForms data binding.
    /// </summary>
    public class KeyWrapper
    {
        private ISshKey key;

        public bool Confirm
        {
            get { return key.HasConstraint(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM); }
        }

        public bool Lifetime
        {
            get { return key.HasConstraint(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME); }
        }

        public bool Destination
        {
            get { return key.DestinationConstraint != null; }
        }

        public string Comment
        {
            get { return key.Comment; }
        }

        public string Source
        {
            get { return key.Source; }
        }

        public string Type
        {
            get { return key.Algorithm.GetIdentifier(); }
        }

        public int Size
        {
            get { return key.Size; }
        }

        public string Fingerprint
        {
            get { return key.GetMD5Fingerprint().ToHexString(); }
        }

        public KeyWrapper(ISshKey key)
        {
            this.key = key;
        }

        public ISshKey GetKey()
        {
            return key;
        }
    }
}
