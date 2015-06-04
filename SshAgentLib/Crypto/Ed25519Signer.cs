//
// Ed25519PublicKeyParameters.cs
//
// Copyright (c) 2015 David Lechner
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

using Chaos.NaCl;
using Org.BouncyCastle.Crypto;
using dlech.SshAgentLib;

namespace dlech.SshAgentLib.Crypto
{
    /// <summary>
    /// Glue to make Chaos.NaCl work with BouncyCastle
    /// </summary>
    public sealed class Ed25519Signer : ISigner
    {
        List<byte> message = new List<byte>();
        Ed25519PrivateKeyParameter privateKey;
        Ed25519PublicKeyParameter publicKey;

        public string AlgorithmName
        {
            get { return PublicKeyAlgorithm.ED25519.GetIdentifierString(); }
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            for (int i = 0; i < length; i++) {
                message.Add(input[inOff + i]);
            }
        }

        public byte[] GenerateSignature()
        {
            if (privateKey == null) {
                throw new InvalidOperationException();
            }
            return Ed25519.Sign(message.ToArray(), privateKey.Signature);
        }

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            if (parameters == null) {
                throw new ArgumentNullException("parameters");
            }
            message.Clear();
            if (forSigning) {
                privateKey = parameters as Ed25519PrivateKeyParameter;
                publicKey = null;
                if (privateKey == null) {
                    throw new ArgumentException("Expecting Ed25519PrivateKeyParameter", "parameters");
                }
            } else {
                publicKey = parameters as Ed25519PublicKeyParameter;
                privateKey = null;
                if (publicKey == null) {
                    throw new ArgumentException("Expecting Ed25519PublicKeyParameter", "parameters");
                }
            }
        }

        public void Reset()
        {
            message.Clear();
        }

        public void Update(byte input)
        {
            message.Add(input);
        }

        public bool VerifySignature(byte[] signature)
        {
            if (publicKey == null) {
                throw new InvalidOperationException();
            }
            return Ed25519.Verify(signature, message.ToArray(), publicKey.Key);
        }
    }
}
