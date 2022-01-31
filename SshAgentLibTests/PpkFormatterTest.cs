//
// PpkFormatterTest.cs
//
// Author(s): David Lechner <david@lechnology.com>
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

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Text;
using dlech.SshAgentLib;
using dlech.SshAgentLib.Crypto;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    ///This is a test class for PpkFileTest and is intended
    ///to contain all PpkFileTest Unit Tests
    ///</summary>
    [TestFixture()]
    public class PpkFormatterTest
    {
        string DllDirectory
        {
            get { return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location); }
        }

        /// <summary>
        ///A test for Deserialize .ppk file with non-ascii chars in passphrase
        ///</summary>
        [Test()]
        public void PpkDeserializeNonAsciiPassphraseTest()
        {
            ISshKey key;
            PpkFormatter formatter = new PpkFormatter();
            formatter.WarnOldFileFormatCallbackMethod = delegate()
            {
                Assert.Fail("Warn old file format was not expected");
            };

            string passphrase = "Ŧéşť";
            formatter.GetPassphraseCallbackMethod = delegate(string comment)
            {
                SecureString result = new SecureString();
                foreach (char c in passphrase)
                {
                    result.AppendChar(c);
                }
                return result;
            };

            string expectedComment = "rsa-key-20120818";

            /* test for successful method call */
            var path = Path.Combine(
                DllDirectory,
                "../../../Resources/ssh2-rsa-non-ascii-passphrase.ppk"
            );
            key = formatter.DeserializeFile(path);
            Assert.AreEqual(expectedComment, key.Comment);
        }

        /// <summary>
        /// Tests Ed25519 ppk file parsing.
        /// </summary>
        [Test]
        public void Ed25519SigTest()
        {
            ISshKey target;

            PpkFormatter formatter = new PpkFormatter()
            {
                GetPassphraseCallbackMethod = _ =>
                {
                    SecureString result = new SecureString();
                    foreach (char c in "PageantSharp")
                    {
                        result.AppendChar(c);
                    }
                    return result;
                }
            };
            string[] keys =
            {
                "../../../Resources/ssh2-ed25519.ppk",
                "../../../Resources/ssh2-ed25519-no-passphrase.ppk"
            };
            string[] sig =
            {
                "01:38:67:b5:b9:cc:a6:a9:9c:cd:38:76:0d:81:66:45:cf:ed:a3:ec:55:ad:"
                    + "40:36:01:ca:13:77:3c:41:4e:8e:49:3d:d6:e5:d9:9c:b1:1f:24:de:a9:4c:"
                    + "a5:bd:3c:08:0a:10:f5:25:c0:ef:bd:4b:4f:17:e2:54:fe:13:ac:74",
                "01:08:c6:d4:1b:3e:51:9c:39:3f:7c:25:a4:fb:13:0f:3c:74:69:67:df:e3:"
                    + "bf:e4:06:fc:4a:1b:da:e3:0b:1f:5d:df:37:6a:d1:1d:b3:31:39:60:20:61:"
                    + "b7:ac:bd:a1:e4:39:fc:b1:b0:a3:4c:9c:8c:02:f2:e1:2d:1c:9e:c8"
            };
            for (int i = 0; i < keys.Length; ++i)
            {
                var path = Path.Combine(DllDirectory, keys[i]);
                target = (ISshKey)formatter.DeserializeFile(path);
                Assert.That(
                    (
                        (Ed25519PrivateKeyParameter)target.GetPrivateKeyParameters()
                    ).Signature.ToHexString(),
                    Is.EqualTo(sig[i]),
                    keys[i]
                );
            }
        }

        [Test]
        public void EcdsaSigTest()
        {
            ISshKey target;

            PpkFormatter formatter = new PpkFormatter()
            {
                GetPassphraseCallbackMethod = _ =>
                {
                    SecureString result = new SecureString();
                    foreach (char c in "PageantSharp")
                    {
                        result.AppendChar(c);
                    }
                    return result;
                }
            };

            string[] keys =
            {
                "../../../Resources/ecdsa-sha2-nistp256.ppk",
                "../../../Resources/ecdsa-sha2-nistp256-no-passphrase.ppk",
                "../../../Resources/ecdsa-sha2-nistp384.ppk",
                "../../../Resources/ecdsa-sha2-nistp384-no-passphrase.ppk",
                "../../../Resources/ecdsa-sha2-nistp521.ppk",
                "../../../Resources/ecdsa-sha2-nistp521-no-passphrase.ppk"
            };
            string[] d =
            {
                "569f23328522cf93694b0cca6bafd7236cf8bea6a9aab098491e915b5d02f2e5",
                "9d4c19af9d289a8aa67d3b636504cd473e054be3373d334b5469e93e0a06be21",
                "200fcb19f9d72b2c0e163ff3869b05beda93536d862bedb5748ba2b6174d4af2aea731dfb8884ae956f4dcf7b138489d",
                "31a122fbf5c674ddbddbc03f96d4f26c534fd5df7eae896a8890c7bdd3de8c5324f06b1efe836870318f23c5a66a2495",
                "14904fd2a509104e86cd9247cf081088caffa124c263caf43ec7cdf5d6ee14a90"
                    + "7de16d30561ed14155fbf651ecc5b66a7d329ffa949aa3dcbdd8efe9ea492a7001",
                "ef41441bc21c20ee38a8169855b618e5c76f34b067d8bbd85276de982aec60fc9"
                    + "0114acad5fc599e83c8d6fc535fb36c5244908577b1138ff4eed7d7b6c9eb2d01"
            };
            for (int i = 0; i < keys.Length; ++i)
            {
                var path = Path.Combine(DllDirectory, keys[i]);
                target = formatter.DeserializeFile(path);
                var priKeyParam = (ECPrivateKeyParameters)target.GetPrivateKeyParameters();
                Assert.That(priKeyParam.D.ToString(16), Is.EqualTo(d[i]));
            }
        }

        /// <summary>
        ///A test for PpkFile ParseData method
        ///</summary>
        [Test()]
        public void PpkFileParseDataTest()
        {
            ISshKey target;

            PpkFormatter.WarnOldFileFormatCallback warnOldFileNotExpected = delegate()
            {
                Assert.Fail("Warn old file format was not expected");
            };
            bool warnCallbackCalled; // set to false before calling warnOldFileExpceted
            PpkFormatter.WarnOldFileFormatCallback warnOldFileExpected = delegate()
            {
                warnCallbackCalled = true;
            };

            string passphrase = "PageantSharp";
            PpkFormatter.GetPassphraseCallback getPassphrase = delegate(string comment)
            {
                SecureString result = new SecureString();
                foreach (char c in passphrase)
                {
                    result.AppendChar(c);
                }
                return result;
            };

            PpkFormatter.GetPassphraseCallback getBadPassphrase = delegate(string comment)
            {
                SecureString result = new SecureString();
                foreach (char c in "badword")
                {
                    result.AppendChar(c);
                }
                return result;
            };

            int expectedKeySize = 1024; // all test keys

            //      string expectedSsh2RsaPublicKeyAlgorithm = PpkFile.PublicKeyAlgorithms.ssh_rsa;
            //      string expectedSsh2RsaWithoutPassPublicKeyString =
            //        "AAAAB3NzaC1yc2EAAAABJQAAAIEAhWqdEs/lz1r4L8ZAAS76rX7hj3rrI/6FNlBw" +
            //        "6ERba2VFmn2AHxQwZmHHmqM+UtiY57angjD9fTbTzL74C0+f/NrRY+BYXf1cF+u5" +
            //        "XmjNKygrsIq3yPMZV4q8YcN/ls9COcynOQMIEmJF6Q0LD7Gt9Uv5yjqc2Ay7VVhG" +
            //        "qZNnIeE=";
            //      string expectedSsh2RsaWithPassPublicKeyString =
            //        "AAAAB3NzaC1yc2EAAAABJQAAAIEAvpwLqhmHYAipvnbQeFEzC7kSTdOCpH5XP9rT" +
            //        "lwScQ5n6Br1DDGIg7tSOBCbralX+0U7NClrcUkueydXRqXEf1rX26o4EcrZ+v1z/" +
            //        "pgu7dbOyHKK0LczCx/IHBm8jrpzrJeB0rg+0ym7XgEcGYgdRj7wFo93PEtx1T4kF" +
            //        "gNLsE3k=";
            //      string expectedSsh2RsaWithoutPassComment = "PageantSharp test: SSH2-RSA, no passphrase";
            string expectedSsh2RsaWithPassComment = "PageantSharp test: SSH2-RSA, with passphrase";
            //      string expectedSsh2RsaWithoutPassPrivateKeyString =
            //        "AAAAgCQO+gUVmA6HSf8S/IqywEqQ/rEoI+A285IjlCMZZNDq8DeXimlDug3VPN2v" +
            //        "lE29/8/sLUXIDSjCtciiUOB2Ypb5Y7AtjDDGg4Yk4v034Mxp0Db6ygDrBuSXbV1U" +
            //        "JzjiDmJOOXgrVLzqc1BZCxVEnzC3fj4GiqQnN1Do3urPatgNAAAAQQDLKWiXIxVj" +
            //        "CoNhzkJqgz0vTIBAaCDJNy9geibZRCHhcQqVk3jN6TscxKhhRYsbEAsTfUPiIPGF" +
            //        "HQaRkd1mwT4dAAAAQQCoHYkHFPqIniQ0oz/ivWAK9mTdl3GRFXP5+mGZQ+9DAl0V" +
            //        "pYOUy7XiCcqVgukYt0+Rj9QNFIcpuAnPfAD6APeVAAAAQClZDkpDCyJX88Vgw7e/" +
            //        "/gbuTJuPv/UGyHI/SSgZcPUBbgmfyj19puHF66+8LTc9unnBF0JyaH9k0dUycFue" +
            //        "LbE=";
            //      string expectedSsh2RsaWithPassDecryptedPrivateKeyString =
            //        "AAAAgE1GLj4KWXn1rJlSwzeyN0nxFUIlUKONKkpRy2a8rg2RczMqIhnG6sGwHeYB" +
            //        "8LxoDVvGABj0ZyhIK53u5kuckF1DiWEcq3IwGIIZqR6JOwMucjbV1pvvzTz3QpUE" +
            //        "fJ+Hj4tHaI7A124D0b/paUmBxOUgeVYXuMls5GZbcl2ApKNdAAAAQQDkXflDxnVr" +
            //        "EXrXAjK+kug3PDdGOPLVPTQRDGwNbuHhSXdVTKAsBdfp9LJZqDzW4LnWhjebeGbj" +
            //        "Kr1ef2VU7cn1AAAAQQDVrHk2uTj27Iwkj31P/WOBXCrmnQ+oAspL3uaJ1rqxg9+F" +
            //        "rq3Dva/y7n0UBRqJ8Y+mdkKQW6oO0usEsEXrVxz1AAAAQF3U8ibnexxDTxhUZdw5" +
            //        "4nzukrnamPWqbZf2RyvQAMA0vw6uW1YNcN6qJxAkt7K5rLg9fsV2ft1FFBcPy+C+" +
            //        "BDw=";
            string expectedSsh2RsaWithoutPassPrivateMACString =
                "77bfa6dc141ed17e4c850d3a95cd6f4ec89cd86b";
            string oldFileFormatSsh2RsaWithoutPassPrivateMACString =
                "dc54d9b526e6d5aeb4832811f2b825e735b218f7";
            //      string expectedSsh2RsaWithPassPrivateMACString =
            //        "e71a6a7b6271875a8264d9d8995f7c81508d6a6c";

            string expectedSsh2DsaWithPassComment = "PageantSharp SSH2-DSA, with passphrase";
            //      string expectedSsh2DsaPrivateKey = "AAAAFQCMF35lBnFwFWyl40y0wTf4lfdhNQ==";

            PpkFormatter formatter = new PpkFormatter();

            /* test for successful method call */
            formatter.GetPassphraseCallbackMethod = getPassphrase;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            var path = Path.Combine(DllDirectory, "../../../Resources/ssh2-rsa.ppk");
            target = formatter.DeserializeFile(path);
            Assert.AreEqual(expectedSsh2RsaWithPassComment, target.Comment);
            Assert.AreEqual(expectedKeySize, target.Size);
            Assert.That(target.Version, Is.EqualTo(SshVersion.SSH2));

            /* read file to string for modification by subsequent tests */
            path = Path.Combine(DllDirectory, "../../../Resources/ssh2-rsa-no-passphrase.ppk");
            byte[] fileData = File.ReadAllBytes(path);
            string withoutPassFileContents;
            byte[] modifiedFileContents;
            MemoryStream modifiedFileContentsStream;
            withoutPassFileContents = Encoding.UTF8.GetString(fileData);

            /* test bad file version */
            modifiedFileContents = Encoding.UTF8.GetBytes(
                withoutPassFileContents.Replace("2", "9")
            );
            modifiedFileContentsStream = new MemoryStream(modifiedFileContents);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.Fail("Exception did not occur");
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<PpkFormatterException>(ex);
                Assert.AreEqual(
                    PpkFormatterException.PpkErrorType.FileVersion,
                    ((PpkFormatterException)ex).PpkError
                );
            }

            /* test bad public key encryption algorithm */
            modifiedFileContents = Encoding.UTF8.GetBytes(
                withoutPassFileContents.Replace("ssh-rsa", "xyz")
            );
            modifiedFileContentsStream = new MemoryStream(modifiedFileContents);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.Fail("Exception did not occur");
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<PpkFormatterException>(ex);
                Assert.AreEqual(
                    PpkFormatterException.PpkErrorType.PublicKeyEncryption,
                    ((PpkFormatterException)ex).PpkError
                );
            }

            /* test bad private key encryption algorithm */
            modifiedFileContents = Encoding.UTF8.GetBytes(
                withoutPassFileContents.Replace("none", "xyz")
            );
            modifiedFileContentsStream = new MemoryStream(modifiedFileContents);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.Fail("Exception did not occur");
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<PpkFormatterException>(ex);
                Assert.AreEqual(
                    PpkFormatterException.PpkErrorType.PrivateKeyEncryption,
                    ((PpkFormatterException)ex).PpkError
                );
            }

            /* test bad file integrity */
            modifiedFileContents = Encoding.UTF8.GetBytes(
                withoutPassFileContents.Replace("no passphrase", "xyz")
            );
            modifiedFileContentsStream = new MemoryStream(modifiedFileContents);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.Fail("Exception did not occur");
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<PpkFormatterException>(ex);
                Assert.AreEqual(
                    PpkFormatterException.PpkErrorType.FileCorrupt,
                    ((PpkFormatterException)ex).PpkError
                );
            }

            /* test bad passphrase */
            path = Path.Combine(DllDirectory, "../../../Resources/ssh2-rsa.ppk");
            fileData = File.ReadAllBytes(path);
            modifiedFileContentsStream = new MemoryStream(fileData);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.Fail("Exception did not occur");
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<CallbackNullException>(ex);
            }
            path = Path.Combine(DllDirectory, "../../../Resources/ssh2-rsa.ppk");
            fileData = File.ReadAllBytes(path);
            modifiedFileContentsStream = new MemoryStream(fileData);
            formatter.GetPassphraseCallbackMethod = getBadPassphrase;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.Fail("Exception did not occur");
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<PpkFormatterException>(ex);
                Assert.AreEqual(
                    PpkFormatterException.PpkErrorType.BadPassphrase,
                    ((PpkFormatterException)ex).PpkError
                );
            }

            /* test old file format */
            modifiedFileContents = Encoding.UTF8.GetBytes(
                withoutPassFileContents
                    .Replace("PuTTY-User-Key-File-2", "PuTTY-User-Key-File-1")
                    .Replace("Private-MAC", "Private-Hash")
                    .Replace(
                        expectedSsh2RsaWithoutPassPrivateMACString,
                        oldFileFormatSsh2RsaWithoutPassPrivateMACString
                    )
            );
            modifiedFileContentsStream = new MemoryStream(modifiedFileContents);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileExpected;
            try
            {
                warnCallbackCalled = false;
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
                Assert.IsTrue(warnCallbackCalled);
            }
            catch (Exception ex)
            {
                Assert.Fail(ex.ToString());
            }

            /* test reading bad file */
            path = Path.Combine(DllDirectory, "../../../Resources/emptyFile.ppk");
            fileData = File.ReadAllBytes(path);
            modifiedFileContentsStream = new MemoryStream(fileData);
            formatter.GetPassphraseCallbackMethod = null;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            try
            {
                target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOf<PpkFormatterException>(ex);
                Assert.AreEqual(
                    PpkFormatterException.PpkErrorType.FileFormat,
                    ((PpkFormatterException)ex).PpkError
                );
            }

            /* test reading SSH2-DSA files */
            path = Path.Combine(DllDirectory, "../../../Resources/ssh2-dsa.ppk");
            fileData = File.ReadAllBytes(path);
            modifiedFileContentsStream = new MemoryStream(fileData);
            formatter.GetPassphraseCallbackMethod = getPassphrase;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            target = (ISshKey)formatter.Deserialize(modifiedFileContentsStream);
            Assert.AreEqual(expectedSsh2DsaWithPassComment, target.Comment);
            Assert.AreEqual(expectedKeySize, target.Size);

            /* test ECDSA and ED25519 keys */

            string[] keys =
            {
                "../../../Resources/ecdsa-sha2-nistp256.ppk",
                "../../../Resources/ecdsa-sha2-nistp256-no-passphrase.ppk",
                "../../../Resources/ecdsa-sha2-nistp384.ppk",
                "../../../Resources/ecdsa-sha2-nistp384-no-passphrase.ppk",
                "../../../Resources/ecdsa-sha2-nistp521.ppk",
                "../../../Resources/ecdsa-sha2-nistp521-no-passphrase.ppk",
                "../../../Resources/ssh2-ed25519.ppk",
                "../../../Resources/ssh2-ed25519-no-passphrase.ppk"
            };
            string[] fps =
            {
                "7c:7b:9b:45:ca:dd:d5:d3:9f:25:e7:68:ec:13:7d:79",
                "80:a9:6e:a1:e4:70:b7:85:ac:e5:df:06:19:95:ce:7d",
                "13:cc:91:2a:1c:d4:e9:38:cc:df:49:a1:23:fa:38:f2",
                "e4:c5:a0:c6:b0:b9:fc:9f:0c:7b:6d:98:70:ce:7a:1c",
                "21:17:40:2e:2a:16:03:f3:ca:79:a2:73:23:f5:ea:d1",
                "ae:a0:a6:e0:6e:2a:1c:c0:fa:2e:3d:47:15:b3:2b:cb",
                "5a:b8:a8:f7:1f:06:d6:3b:30:60:a6:41:a0:1f:88:e5",
                "e4:41:53:cb:04:83:13:b3:58:98:ac:a7:c5:c8:0c:00"
            };
            PublicKeyAlgorithm[] algs =
            {
                PublicKeyAlgorithm.ECDSA_SHA2_NISTP256,
                PublicKeyAlgorithm.ECDSA_SHA2_NISTP256,
                PublicKeyAlgorithm.ECDSA_SHA2_NISTP384,
                PublicKeyAlgorithm.ECDSA_SHA2_NISTP384,
                PublicKeyAlgorithm.ECDSA_SHA2_NISTP521,
                PublicKeyAlgorithm.ECDSA_SHA2_NISTP521,
                PublicKeyAlgorithm.ED25519,
                PublicKeyAlgorithm.ED25519
            };
            string[] comments =
            {
                "PageantSharp ecdsa-sha2-nistp256, with passphrase",
                "PageantSharp ecdsa-sha2-nistp256, no passphrase",
                "PageantSharp ecdsa-sha2-nistp384, with passphrase",
                "PageantSharp ecdsa-sha2-nistp384, no passphrase",
                "PageantSharp ecdsa-sha2-nistp521, with passphrase",
                "PageantSharp ecdsa-sha2-nistp521, no passphrase",
                "PageantSharp ssh2-ed25519, with passphrase",
                "PageantSharp ssh2-ed25519, no passphrase"
            };
            int[] sizes = { 256, 256, 384, 384, 521, 521, 256, 256 };
            formatter.GetPassphraseCallbackMethod = getPassphrase;
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            for (int i = 0; i < keys.Length; ++i)
            {
                path = Path.Combine(DllDirectory, keys[i]);
                target = (ISshKey)formatter.DeserializeFile(path);
                Assert.That(target.Size, Is.EqualTo(sizes[i]));
                Assert.That(target.Algorithm, Is.EqualTo(algs[i]));
                Assert.That(target.GetMD5Fingerprint().ToHexString(), Is.EqualTo(fps[i]));
                Assert.That(target.Comment, Is.EqualTo(comments[i]));
            }
        }

        [Test]
        public void ParsePpkv3()
        {
            ISshKey target;

            PpkFormatter.WarnOldFileFormatCallback warnOldFileNotExpected = () =>
            {
                Assert.Fail("Warn old file format was not expected");
            };

            Func<string, PpkFormatter.GetPassphraseCallback> GetPassphrase = v =>
            {
                return (comment) =>
                {
                    if (comment == null)
                    {
                        return null;
                    }
                    SecureString result = new SecureString();
                    foreach (char c in v)
                    {
                        result.AppendChar(c);
                    }
                    return result;
                };
            };

            string passphraseNonAscii = "Ŧéşť";
            string passphraseGood = "PageantSharp";
            // string passphraseBad = "badword";
            string passphraseNull = null;

            int expectedKeySize = 1024; // all test keys

            string path;
            PpkFormatter formatter = new PpkFormatter();

            /* test for successful method call */
            formatter.GetPassphraseCallbackMethod = GetPassphrase(passphraseGood);
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            path = Path.Combine(DllDirectory, "../../../Resources/ssh2-rsa-v3.ppk");
            target = formatter.DeserializeFile(path);
            Assert.AreEqual("PageantSharp test: SSH2-RSA PPKv3, with passphrase", target.Comment);
            Assert.AreEqual(expectedKeySize, target.Size);
            Assert.That(target.Version, Is.EqualTo(SshVersion.SSH2));

            formatter.GetPassphraseCallbackMethod = GetPassphrase(passphraseNonAscii);
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            path = Path.Combine(
                DllDirectory,
                "../../../Resources/ssh2-rsa-v3-non-ascii-passphrase.ppk"
            );
            target = formatter.DeserializeFile(path);
            Assert.AreEqual(
                "PageantSharp test: SSH2-RSA PPKv3, non ascii passphrase",
                target.Comment
            );
            Assert.AreEqual(expectedKeySize, target.Size);
            Assert.That(target.Version, Is.EqualTo(SshVersion.SSH2));

            formatter.GetPassphraseCallbackMethod = GetPassphrase(passphraseNull);
            formatter.WarnOldFileFormatCallbackMethod = warnOldFileNotExpected;
            path = Path.Combine(DllDirectory, "../../../Resources/ssh2-rsa-v3-no-passphrase.ppk");
            target = formatter.DeserializeFile(path);
            Assert.AreEqual("PageantSharp test: SSH2-RSA PPKv3, no passphrase", target.Comment);
            Assert.AreEqual(expectedKeySize, target.Size);
            Assert.That(target.Version, Is.EqualTo(SshVersion.SSH2));
        }
    }
}
