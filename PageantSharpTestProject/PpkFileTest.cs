using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Diagnostics;
using System.IO;
using PageantSharpTestProject.Properties;
using System.Text;
using System.Security.Cryptography;
using System.Security;

namespace PageantSharpTestProject
{


	/// <summary>
	///This is a test class for PpkFileTest and is intended
	///to contain all PpkFileTest Unit Tests
	///</summary>
	[TestClass()]
	public class PpkFileTest
	{


		private TestContext testContextInstance;

		/// <summary>
		///Gets or sets the test context which provides
		///information about and functionality for the current test run.
		///</summary>
		public TestContext TestContext
		{
			get
			{
				return testContextInstance;
			}
			set
			{
				testContextInstance = value;
			}
		}

		#region Additional test attributes
		// 
		//You can use the following additional attributes as you write your tests:
		//
		//Use ClassInitialize to run code before running the first test in the class
		//[ClassInitialize()]
		//public static void MyClassInitialize(TestContext testContext)
		//{
		//}
		//
		//Use ClassCleanup to run code after all tests in a class have run
		//[ClassCleanup()]
		//public static void MyClassCleanup()
		//{
		//}
		//
		//Use TestInitialize to run code before running each test
		//[TestInitialize()]
		//public void MyTestInitialize()
		//{
		//}
		//
		//Use TestCleanup to run code after each test has run
		//[TestCleanup()]
		//public void MyTestCleanup()
		//{
		//}
		//
		#endregion



		public void PpkFileReadFileTest()
		{
			PpkKey target;

			Assembly asm = Assembly.GetExecutingAssembly();
			string dir = Path.GetDirectoryName(asm.Location);
			string emptyFileName = Path.Combine(dir, @"Resources\emptyFile.ppk");
			string withoutPassFileName = Path.Combine(dir, @"Resources\withoutPassphrase.ppk");
			string withPassFileName = Path.Combine(dir, @"Resources\withPassphrase.ppk");
		}

		/// <summary>
		///A test for PpkFile ParseData method
		///</summary>
		[TestMethod()]
		public void PpkFileParseDataTest()
		{
			PpkKey target;

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

			string expectedSsh2RsaPublicKeyAlgorithm = PpkFile.PublicKeyAlgorithms.ssh_rsa;
			string expectedSsh2RsaWithoutPassPublicKeyString = 
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAhWqdEs/lz1r4L8ZAAS76rX7hj3rrI/6FNlBw" +
				"6ERba2VFmn2AHxQwZmHHmqM+UtiY57angjD9fTbTzL74C0+f/NrRY+BYXf1cF+u5" +
				"XmjNKygrsIq3yPMZV4q8YcN/ls9COcynOQMIEmJF6Q0LD7Gt9Uv5yjqc2Ay7VVhG" +
				"qZNnIeE=";
			string expectedSsh2RsaWithPassPublicKeyString = 
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAvpwLqhmHYAipvnbQeFEzC7kSTdOCpH5XP9rT" +
				"lwScQ5n6Br1DDGIg7tSOBCbralX+0U7NClrcUkueydXRqXEf1rX26o4EcrZ+v1z/" +
				"pgu7dbOyHKK0LczCx/IHBm8jrpzrJeB0rg+0ym7XgEcGYgdRj7wFo93PEtx1T4kF" +
				"gNLsE3k=";
			string expectedSsh2RsaWithoutPassComment = "PageantSharp test: SSH2-RSA, no passphrase";
			string expectedSsh2RsaWithPassComment = "PageantSharp test: SSH2-RSA, with passphrase";
			string expectedSsh2RsaWithoutPassPrivateKeyString =
				"AAAAgCQO+gUVmA6HSf8S/IqywEqQ/rEoI+A285IjlCMZZNDq8DeXimlDug3VPN2v" +
				"lE29/8/sLUXIDSjCtciiUOB2Ypb5Y7AtjDDGg4Yk4v034Mxp0Db6ygDrBuSXbV1U" +
				"JzjiDmJOOXgrVLzqc1BZCxVEnzC3fj4GiqQnN1Do3urPatgNAAAAQQDLKWiXIxVj" +
				"CoNhzkJqgz0vTIBAaCDJNy9geibZRCHhcQqVk3jN6TscxKhhRYsbEAsTfUPiIPGF" +
				"HQaRkd1mwT4dAAAAQQCoHYkHFPqIniQ0oz/ivWAK9mTdl3GRFXP5+mGZQ+9DAl0V" +
				"pYOUy7XiCcqVgukYt0+Rj9QNFIcpuAnPfAD6APeVAAAAQClZDkpDCyJX88Vgw7e/" +
				"/gbuTJuPv/UGyHI/SSgZcPUBbgmfyj19puHF66+8LTc9unnBF0JyaH9k0dUycFue" +
				"LbE=";
			string expectedSsh2RsaWithPassDecryptedPrivateKeyString = 
				"AAAAgE1GLj4KWXn1rJlSwzeyN0nxFUIlUKONKkpRy2a8rg2RczMqIhnG6sGwHeYB" +
				"8LxoDVvGABj0ZyhIK53u5kuckF1DiWEcq3IwGIIZqR6JOwMucjbV1pvvzTz3QpUE" +
				"fJ+Hj4tHaI7A124D0b/paUmBxOUgeVYXuMls5GZbcl2ApKNdAAAAQQDkXflDxnVr" +
				"EXrXAjK+kug3PDdGOPLVPTQRDGwNbuHhSXdVTKAsBdfp9LJZqDzW4LnWhjebeGbj" +
				"Kr1ef2VU7cn1AAAAQQDVrHk2uTj27Iwkj31P/WOBXCrmnQ+oAspL3uaJ1rqxg9+F" +
				"rq3Dva/y7n0UBRqJ8Y+mdkKQW6oO0usEsEXrVxz1AAAAQF3U8ibnexxDTxhUZdw5" +
				"4nzukrnamPWqbZf2RyvQAMA0vw6uW1YNcN6qJxAkt7K5rLg9fsV2ft1FFBcPy+C+" +
				"BDw=";
			string expectedSsh2RsaWithoutPassPrivateMACString = 
				"77bfa6dc141ed17e4c850d3a95cd6f4ec89cd86b";
			string oldFileFormatSsh2RsaWithoutPassPrivateMACString = 
				"dc54d9b526e6d5aeb4832811f2b825e735b218f7";
			string expectedSsh2RsaWithPassPrivateMACString = 
				"e71a6a7b6271875a8264d9d8995f7c81508d6a6c";

			string expectedSsh2DsaWithPassComment = "PageantSharp SSH2-DSA, with passphrase";
			string expectedSsh2DsaPrivateKey = "AAAAFQCMF35lBnFwFWyl40y0wTf4lfdhNQ==";
		

			/* test for successful method call */
			target = PpkFile.ParseData(Resources.ssh2_rsa_ppk, getPassphrase, warnOldFileNotExpected);
			Assert.AreEqual(expectedSsh2RsaWithPassComment, target.Comment);
			Assert.AreEqual(expectedKeySize, target.Size);
			
			/* read file to string for modification by subsequent tests */
			string withoutPassFileContents;
			byte[] modifiedFileContents;
			withoutPassFileContents = Encoding.UTF8.GetString(Resources.ssh2_rsa_no_passphrase_ppk);

			/* test bad file version */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("2", "3"));
			try {
				target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.FileVersion, ((PpkFileException)ex).Error);
			}

			/* test bad public key encryption algorithm */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("ssh-rsa", "xyz"));
			try {
				target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.PublicKeyEncryption, ((PpkFileException)ex).Error);
			}

			/* test bad private key encryption algorithm */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("none", "xyz"));
			try {
				target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.PrivateKeyEncryption, ((PpkFileException)ex).Error);
			}

			/* test bad file integrity */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("no passphrase", "xyz"));
			try {
				target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.FileCorrupt, ((PpkFileException)ex).Error);
			}

			/* test bad passphrase */
			try {
				target = PpkFile.ParseData(Resources.ssh2_rsa_ppk, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.BadPassphrase, ((PpkFileException)ex).Error);
			}
			try {
				target = PpkFile.ParseData(Resources.ssh2_rsa_ppk, getBadPassphrase, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.BadPassphrase, ((PpkFileException)ex).Error);
			}

			/* test old file format */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents
				.Replace("PuTTY-User-Key-File-2", "PuTTY-User-Key-File-1")
				.Replace("Private-MAC", "Private-Hash")
				.Replace(expectedSsh2RsaWithoutPassPrivateMACString, oldFileFormatSsh2RsaWithoutPassPrivateMACString));
			try {
				warnCallbackCalled = false;
				target = PpkFile.ParseData(modifiedFileContents, null, warnOldFileExpected);
				Assert.IsTrue(warnCallbackCalled);
			} catch (Exception ex) {
				Assert.Fail(ex.ToString());
			}

			/* test reading bad file */
			try {
				target = PpkFile.ParseData(Resources.emptyFile_ppk, null, warnOldFileNotExpected);
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.FileFormat, ((PpkFileException)ex).Error);
			}

			/* test reading SSH2-DSA files */
			target = PpkFile.ParseData(Resources.ssh2_dsa_ppk, getPassphrase, warnOldFileNotExpected);
			Assert.AreEqual(expectedSsh2DsaWithPassComment, target.Comment);
			Assert.AreEqual(expectedKeySize, target.Size);
		}

        /// <summary>
		/// A test for keys with non-standard length (bits)
        /// See github issue #2
		///</summary>
        [TestMethod()]
        public void NonStandardLengthTest()
        {
            PpkFile.WarnOldFileFormatCallback warnOldFileNotExpected = delegate()
            {
                Assert.Fail("Warn old file format was not expected");
            };

            PpkKey target;
            for (int i = 5; i < 10; i++) {
                target = PpkFile.ReadFile("C:\\Temp\\" + i + ".ppk", null, warnOldFileNotExpected);
            }
            
        }
				
	}
}
