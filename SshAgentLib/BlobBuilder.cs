//
// BlobBuilder.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013,2017 David Lechner
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
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// used to build blobs that are used for storing and sending keys
    /// in open-ssh/PuTTY format
    /// </summary>
    public class BlobBuilder
    {
        List<byte> byteList;

        /// <summary>
        /// Gets current length of blob
        /// </summary>
        public int Length
        {
            get { return byteList.Count; }
        }

        /// <summary>
        /// Creates new instance of BlobBuilder
        /// </summary>
        public BlobBuilder()
        {
            byteList = new List<byte>();
        }

        ~BlobBuilder()
        {
            Clear();
        }

        /// <summary>
        /// Adds byte to the blob
        /// </summary>
        public void AddUInt8(byte value)
        {
            byteList.Add(value);
        }

        public void AddInt(int value)
        {
            AddUInt32((uint)value);
        }

        public void AddUInt32(uint value)
        {
            byteList.AddRange(value.ToBytes());
        }

        public void AddUInt64(ulong value)
        {
            byteList.AddRange(value.ToBytes());
        }

        /// <summary>
        /// Adds byte[] to the blob
        /// </summary>
        /// <param name="bytes"></param>
        public void AddBytes(byte[] bytes)
        {
            byteList.AddRange(bytes);
        }

        /// <summary>
        /// Adds a string to the blob
        /// </summary>
        /// <param name="value">the string to add</param>
        public void AddStringBlob(string value)
        {
            AddBlob(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Adds BigInteger to builder prefixed with size
        /// </summary>
        /// <param name="value"></param>
        public void AddBigIntBlob(BigInteger value)
        {
            byte[] bytes = value.ToByteArray();
            AddBlob(bytes);
        }

        /// <summary>
        /// Adds byte[] to builder as Ssh1 sub-blob
        /// </summary>
        /// <param name="value"></param>
        public void AddSsh1BigIntBlob(BigInteger value)
        {
            ushort size = (ushort)(value.BitLength);
            AddUInt8((byte)((size >> 8) & 0xFF));
            AddUInt8((byte)(size & 0xFF));
            byte[] bytes = value.ToByteArrayUnsigned();
            byteList.AddRange(bytes);
        }

        /// <summary>
        /// Adds byte[] to builder as sub-blob
        /// </summary>
        /// <param name="blob"></param>
        public void AddBlob(byte[] blob)
        {
            byteList.AddRange(blob.Length.ToBytes());
            byteList.AddRange(blob);
        }

        /// <summary>
        /// Prepends header 
        /// </summary>
        /// <param name="message">message number to include in header</param>
        /// <param name="headerData">data to include in header</param>
        public void InsertHeader(Agent.Message message, int headerData)
        {
            byteList.InsertRange(0, headerData.ToBytes());
            InsertHeader(message);
        }

        /// <summary>
        /// Prepends header 
        /// </summary>
        /// <param name="message">message number to include in header</param>
        public void InsertHeader(Agent.Message message)
        {
            byteList.Insert(0, (byte)message);
            byte[] blobLength = byteList.Count.ToBytes();
            byteList.InsertRange(0, blobLength);
        }

        /// <summary>
        /// Gets the resulting blob from the blob builder.
        /// </summary>
        /// <returns>byte[] containing the blob</returns>
        public byte[] GetBlob()
        {
            return byteList.ToArray();
        }

        public PinnedArray<byte> GetBlobAsPinnedByteArray()
        {
            return new PinnedArray<byte>(GetBlob());
        }

        /// <summary>
        /// Writes 0 to all values, then clears list
        /// </summary>
        public void Clear()
        {
            Util.ClearByteList(byteList);
        }
    }
}
