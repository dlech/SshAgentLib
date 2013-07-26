//
// UtilTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
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

using System.Security.Cryptography;
using dlech.SshAgentLib;
using NUnit.Framework;

namespace dlech.SshAgentLibTests
{

  /// <summary>
  ///This is a test class for PSUtilTest and is intended
  ///to contain all PSUtilTest Unit Tests
  ///</summary>
  [TestFixture()]
  public class UtilTest
  {
    /// <summary>
    ///A test for TrimLeadingZero
    ///</summary>
    [Test()]
    public void TrimLeadingZeroTest()
    {
      PinnedArray<byte> array1 = new PinnedArray<byte>(new byte[] { 1, 2, 3, 4 });
      Util.TrimLeadingZero(array1);
      Assert.That(array1.Data, Is.EqualTo(new byte[]{ 1, 2, 3, 4 }));

      PinnedArray<byte> array2 = new PinnedArray<byte>(new byte[] { 0, 1, 2, 3, 4 });
      Util.TrimLeadingZero(array2);
      Assert.That(array2.Data, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
    }

    /// <summary>
    ///A test for ModMinusOne
    ///</summary>
    [Test()]
    public void ModMinusOneTest()
    {
      RSAParameters p;
      using (RSA rsa = RSA.Create()) {
        p = rsa.ExportParameters(true);
      }
      PinnedArray<byte> a = new PinnedArray<byte>(p.D);
      PinnedArray<byte> b = new PinnedArray<byte>(p.P);
      byte[] expected = p.DP;
     
      PinnedArray<byte> actual;
      actual = Util.ModMinusOne(a, b);
      Assert.That(actual.Data, Is.EqualTo(expected));
    }
  }
}
