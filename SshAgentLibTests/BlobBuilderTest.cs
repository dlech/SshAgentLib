//
// BlobBuilderTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013 David Lechner
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
using System.Linq;
using System.Text;
using dlech.SshAgentLib;
using NUnit.Framework;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    /// Test for BlobBuilder class
    /// </summary>
    [TestFixture()]
    class BlobBuilderTest
    {
        [Test()]
        public void TestAddBytes()
        {
            var builder = new BlobBuilder();
            byte[] value = { 0, 1, 2, 3, 4, 5 };
            builder.AddBytes(value);
            Assert.That(builder.GetBlob(), Is.EqualTo(value));
        }

        [Test()]
        public void TestAddInt()
        {
            var builder = new BlobBuilder();
            UInt32 value = 12345;
            builder.AddUInt32(value);
            Assert.That(builder.GetBlob(), Is.EqualTo(value.ToBytes()));
        }

        [Test]
        public void TestAddDateTime()
        {
            var builder = new BlobBuilder();

            builder.AddUInt64(DateTime.MinValue);
            Assert.That(builder.GetBlob(), Is.EqualTo(new byte[8]));

            builder.Clear();

            builder.AddUInt64(DateTime.MaxValue);
            Assert.That(builder.GetBlob(), Is.EqualTo(Enumerable.Repeat((byte)0xff, 8).ToArray()));

            builder.Clear();

            builder.AddUInt64(DateTime.Parse("2009-02-13T23:31:30"));
            Assert.That(builder.GetBlob(), Is.EqualTo(1234567890L.ToBytes()));
        }

        [Test()]
        public void TestAddBlob()
        {
            var builder = new BlobBuilder();
            byte[] blob = { 0, 1, 2, 3, 4, 5 };
            builder.AddBlob(blob);
            var expected = new byte[blob.Length + 4];
            Array.Copy(blob.Length.ToBytes(), expected, 4);
            Array.Copy(blob, 0, expected, 4, blob.Length);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));
        }

        [Test()]
        public void TestAddString()
        {
            var builder = new BlobBuilder();
            var value = "test string";
            builder.AddStringBlob(value);
            var valueBytes = Encoding.UTF8.GetBytes(value);
            var expected = new byte[valueBytes.Length + 4];
            Array.Copy(valueBytes.Length.ToBytes(), expected, 4);
            Array.Copy(valueBytes, 0, expected, 4, valueBytes.Length);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));
        }

        [Test()]
        public void TestAddBigInt()
        {
            var builder = new BlobBuilder();
            var value = new BigInteger("12398259028592293582039293420948023");
            builder.AddBigIntBlob(value);
            var valueBytes = value.ToByteArrayUnsigned();
            //Assert.That(valueBytes[0], Is.EqualTo(0));
            var expected = new byte[valueBytes.Length + 4];
            Array.Copy(valueBytes.Length.ToBytes(), expected, 4);
            Array.Copy(valueBytes, 0, expected, 4, valueBytes.Length);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));
        }

        [Test()]
        public void TestAddSsh1BigIntBlob()
        {
            var builder = new BlobBuilder();
            var value = new BigInteger("12398259028592293582039293420948023");
            builder.AddSsh1BigIntBlob(value);
            var valueBytes = value.ToByteArrayUnsigned();
            var expected = new byte[valueBytes.Length + 2];

            var size = (ushort)(value.BitLength);
            expected[0] = (byte)((size >> 8) & 0xFF);
            expected[1] = (byte)(size & 0xFF);

            Array.Copy(valueBytes, 0, expected, 2, valueBytes.Length);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));
        }

        [Test()]
        public void TestInsertHeader()
        {
            var builder = new BlobBuilder();
            builder.InsertHeader(Agent.Message.SSH_AGENT_SUCCESS);
            byte[] expected = { 0, 0, 0, 1, (byte)Agent.Message.SSH_AGENT_SUCCESS };
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));

            builder = new BlobBuilder();
            var value1 = 12345;
            builder.InsertHeader(Agent.Message.SSH_AGENT_SUCCESS, value1);
            expected = new byte[9];
            Array.Copy((5).ToBytes(), expected, 4);
            expected[4] = (byte)Agent.Message.SSH_AGENT_SUCCESS;
            Array.Copy(value1.ToBytes(), 0, expected, 5, 4);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));

            builder = new BlobBuilder();
            byte[] value2 = { 1, 2, 3, 4, 5 };
            builder.AddBytes(value2);
            builder.InsertHeader(Agent.Message.SSH_AGENT_SUCCESS);
            expected = new byte[5 + value2.Length];
            var length = value2.Length + 1;
            Array.Copy(length.ToBytes(), expected, 4);
            expected[4] = (byte)Agent.Message.SSH_AGENT_SUCCESS;
            Array.Copy(value2, 0, expected, 5, value2.Length);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));

            builder = new BlobBuilder();
            builder.AddBytes(value2);
            builder.InsertHeader(Agent.Message.SSH_AGENT_SUCCESS, value1);
            expected = new byte[9 + value2.Length];
            Array.Copy((5 + value2.Length).ToBytes(), expected, 4);
            expected[4] = (byte)Agent.Message.SSH_AGENT_SUCCESS;
            Array.Copy(value1.ToBytes(), 0, expected, 5, 4);
            Array.Copy(value2, 0, expected, 9, value2.Length);
            Assert.That(builder.GetBlob(), Is.EqualTo(expected));
        }
    }
}
