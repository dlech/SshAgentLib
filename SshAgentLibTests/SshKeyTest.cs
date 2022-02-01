//
// SshKeyTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013,2015 David Lechner
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

using dlech.SshAgentLib;
using SshAgentLibTests.Properties;
using NUnit.Framework;
using System;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    ///This is a test class for SshKey and is intended
    ///to contain all SshKey Unit Tests
    ///</summary>
    [TestFixture]
    public class SshKeyTest
    {
        /// <summary>
        ///A test for GetFingerprint
        ///</summary>
        [Test]
        public void GetFingerprintTest()
        {
            var formatter1 = new Ssh1KeyFormatter();

            var rsaSsh1Target = formatter1.Deserialize(Resources.rsa1_1);
            var rsaSsh1ExpectedFingerprint = Resources.rsa1_1_fp.Trim();
            var rsaSsh1Actual = "MD5:" + rsaSsh1Target.GetMD5Fingerprint().ToHexString();
            Assert.That(rsaSsh1ExpectedFingerprint, Is.EqualTo(rsaSsh1Actual));

            var formatter2 = new PpkFormatter();

            var rsaTarget = formatter2.Deserialize(Resources.ssh2_rsa_no_passphrase_ppk);
            var rsaExpectedFingerprint = "57:95:98:7f:c2:4e:98:1d:b9:5b:45:fe:6d:a4:6b:17";
            var rsaActual = rsaTarget.GetMD5Fingerprint().ToHexString();
            Assert.That(rsaExpectedFingerprint, Is.EqualTo(rsaActual));

            var dsaTarget = formatter2.Deserialize(Resources.ssh2_dsa_no_passphrase_ppk);
            var dsaExpectedFingerprint = "4e:f1:fc:5d:80:5b:37:b6:13:67:ce:df:4e:83:7b:0b";
            var dsaActual = dsaTarget.GetMD5Fingerprint().ToHexString();
            Assert.That(dsaExpectedFingerprint, Is.EqualTo(dsaActual));
        }

        /// <summary>
        ///A test for GetSSH2PublicKeyBlob
        ///</summary>
        [Test]
        public void GetSSH2PublicKeyBlobTest()
        {
            byte[] actual,
                expected;
            PpkFormatter formatter = new PpkFormatter();
            ISshKey target;

            /* test RSA key */
            target = formatter.Deserialize(Resources.ssh2_rsa_no_passphrase_ppk);
            expected = Convert.FromBase64String(
                "AAAAB3NzaC1yc2EAAAABJQAAAIEAhWqdEs/lz1r4L8ZAAS76rX7hj3rrI/6FNlBw"
                    + "6ERba2VFmn2AHxQwZmHHmqM+UtiY57angjD9fTbTzL74C0+f/NrRY+BYXf1cF+u5"
                    + "XmjNKygrsIq3yPMZV4q8YcN/ls9COcynOQMIEmJF6Q0LD7Gt9Uv5yjqc2Ay7VVhG"
                    + "qZNnIeE="
            );

            actual = target.GetPublicKeyBlob();
            Assert.That(expected, Is.EqualTo(actual));

            /* test DSA key */
            target = formatter.Deserialize(Resources.ssh2_dsa_no_passphrase_ppk);
            expected = Convert.FromBase64String(
                "AAAAB3NzaC1kc3MAAACBAMXDM56ty6fV+qDpMyZxobn5VB4L/E6zvOibUead6HBc"
                    + "OHUibA97EKgooUbqJ9qFUOhhw8TaFtN0UtTLZoHjOWN3JdyugK+f2HYIxvhlvW60"
                    + "8g0lfDU0G4KIXdZukTYm66C0jVSCIdHQ1Iz219JeaEZK00v6wEW7Pp7T7yE71W65"
                    + "AAAAFQDcFrJ83lxI15fUnVl6TSYjB0H7IwAAAIAGatuDAwP1rkYqRH3MbwUTOpzr"
                    + "k/qBYkWbM/8iJlYaWiHjl0rG0HxnwY8Dvb9Knk7Qp6KC8l58KRAiGMrOLBOfPntE"
                    + "gejaXSejM6OARoOtt31IXfOMkbsjAFKFssN+RUDnTPvXPpcL5C3rO1Up4hO3FPqi"
                    + "JQJpL50gTHnDG2Q4BgAAAIA7w6OX/G/pXHDU0M7xXtTN2SOhFQwP8+Tc6h9/Yw/w"
                    + "M9zBXkqb5bdlqy9vRx72/1DXOjH08PIbvza7HfOLkhRri0TYBDJbufQOlK4vQPqF"
                    + "0qhxkYfsgqrZBMBKbLKTZnNm+BW2dgu+QSud67b01IZPzS2i0Z4DgSja9vl3xong"
                    + "Cw=="
            );
            actual = target.GetPublicKeyBlob();
            Assert.That(expected, Is.EqualTo(actual));
        }
    }
}
