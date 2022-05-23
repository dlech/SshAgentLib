//
// KeyWrapper.cs
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

using SshAgentLib.Keys;

namespace dlech.SshAgentLib
{
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

        public OpensshCertificateInfo Certificate
        {
            get { return key.Certificate; }
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
