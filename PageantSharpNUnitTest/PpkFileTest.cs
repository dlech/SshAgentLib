using System;
using NUnit.Framework;
using System.Reflection;
using System.IO;
using dlech.PageantSharp;
using System.Security;
using System.Text;
using System.Resources;

namespace PageantSharpTest
{

  /// <summary>
  ///This is a test class for PpkFileTest and is intended
  ///to contain all PpkFileTest Unit Tests
  ///</summary>
  [TestFixture()]
  public class PpkFileTest
  {

    /// <summary>
    ///A test for PpkFile with non-ascii chars in passphrase
    ///</summary>
    [Test()]
    public void PpkNonAsciiPassphraseTest()
    {
      SshKey target;

      PpkFile.WarnOldFileFormatCallback warnOldFileNotExpected = delegate()
      {
        Assert.Fail("Warn old file format was not expected");
      };

      string passphrase = "Ŧéşť";

      PpkFile.GetPassphraseCallback getPassphrase = delegate()
      {
        SecureString result = new SecureString();
        foreach (char c in passphrase) {
          result.AppendChar(c);
        }
        return result;
      };

      string expectedComment = "rsa-key-20120818";

      /* test for successful method call */
      byte[] fileData = File.ReadAllBytes("../../../Resources/ssh2-rsa-non-ascii-passphrase.ppk");
      target = PpkFile.ParseData(fileData, getPassphrase, warnOldFileNotExpected);

      Assert.AreEqual(expectedComment, target.Comment);
    }

    /// <summary>
    ///A test for PpkFile ParseData method
    ///</summary>
    [Test()]
    public void PpkFileParseDataTest()
    {
      SshKey target;

      PpkFile.WarnOldFileFormatCallback warnOldFileNotExpected = delegate()
      {
        Assert.Fail("Warn old file format was not expected");
      };
      bool warnCallbackCalled; // set to false before calling warnOldFileExpceted
      PpkFile.WarnOldFileFormatCallback warnOldFileExpected = delegate()
      {
        warnCallbackCalled = true;
      };

      string passphrase = "PageantSharp";
      PpkFile.GetPassphraseCallback getPassphrase = delegate()
      {
        SecureString result = new SecureString();
        foreach (char c in passphrase) {
          result.AppendChar(c);
        }
        return result;
      };


      PpkFile.GetPassphraseCallback getBadPassphrase = delegate()
      {
        SecureString result = new SecureString();
        foreach (char c in "badword") {
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


       /* test for successful method call */
      byte[] fileData = File.ReadAllBytes("../../../Resources/ssh2-rsa.ppk");
      target = PpkFile.ParseData(fileData, getPassphrase, warnOldFileNotExpected);
      Assert.AreEqual(expectedSsh2RsaWithPassComment, target.Comment);
      Assert.AreEqual(expectedKeySize, target.Size);
      Assert.That(target.Version, Is.EqualTo(SshVersion.SSH2));

      /* read file to string for modification by subsequent tests */
      fileData = File.ReadAllBytes("../../../Resources/ssh2-rsa-no-passphrase.ppk");
      string withoutPassFileContents;
      byte[] modifiedFileContents;
      withoutPassFileContents = Encoding.UTF8.GetString(fileData);

      /* test bad file version */
      modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("2", "3"));
      try {
        target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
        Assert.Fail("Exception did not occur");
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.FileVersion, ((PpkFileException)ex).Error);
      }

      /* test bad public key encryption algorithm */
      modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("ssh-rsa", "xyz"));
      try {
        target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
        Assert.Fail("Exception did not occur");
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.PublicKeyEncryption, ((PpkFileException)ex).Error);
      }

      /* test bad private key encryption algorithm */
      modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("none", "xyz"));
      try {
        target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
        Assert.Fail("Exception did not occur");
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.PrivateKeyEncryption, ((PpkFileException)ex).Error);
      }

      /* test bad file integrity */
      modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("no passphrase", "xyz"));
      try {
        target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
        Assert.Fail("Exception did not occur");
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.FileCorrupt, ((PpkFileException)ex).Error);
      }

      /* test bad passphrase */
      fileData = File.ReadAllBytes("../../../Resources/ssh2-rsa.ppk");
      try {
        target = PpkFile.ParseData(fileData, null, warnOldFileNotExpected);
        Assert.Fail("Exception did not occur");
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.BadPassphrase, ((PpkFileException)ex).Error);
      }
      fileData = File.ReadAllBytes("../../../Resources/ssh2-rsa.ppk");
      try {
        target = PpkFile.ParseData(fileData, getBadPassphrase, warnOldFileNotExpected);
        Assert.Fail("Exception did not occur");
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.BadPassphrase, ((PpkFileException)ex).Error);
      }

      /* test old file format */
      modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents
        .Replace("PuTTY-User-Key-File-2", "PuTTY-User-Key-File-1")
        .Replace("Private-MAC", "Private-Hash")
        .Replace(expectedSsh2RsaWithoutPassPrivateMACString,
               oldFileFormatSsh2RsaWithoutPassPrivateMACString));
      try {
        warnCallbackCalled = false;
        target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileExpected);
        Assert.IsTrue(warnCallbackCalled);
      } catch (Exception ex) {
        Assert.Fail(ex.ToString());
      }

      /* test reading bad file */
      fileData = File.ReadAllBytes("../../../Resources/emptyFile.ppk");
      try {
        target = PpkFile.ParseData(fileData, null, warnOldFileNotExpected);
      } catch (Exception ex) {
        Assert.IsInstanceOf<PpkFileException>(ex);
        Assert.AreEqual(PpkFileException.ErrorType.FileFormat, ((PpkFileException)ex).Error);
      }

      /* test reading SSH2-DSA files */
      fileData = File.ReadAllBytes("../../../Resources/ssh2-dsa.ppk");
      target = PpkFile.ParseData(fileData, getPassphrase, warnOldFileNotExpected);
      Assert.AreEqual(expectedSsh2DsaWithPassComment, target.Comment);
      Assert.AreEqual(expectedKeySize, target.Size);
    }
  }
}

