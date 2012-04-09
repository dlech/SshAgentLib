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

	
		/// <summary>
		///A test for PpkFile Constructor
		///</summary>
		[TestMethod()]
		public void PpkFileConstructorTest()
		{
			PpkFile target;

			Assembly asm = Assembly.GetExecutingAssembly();
			string dir = Path.GetDirectoryName(asm.Location);
			string emptyFileName = Path.Combine(dir, @"Resources\emptyFile.ppk");
			string withoutPassFileName = Path.Combine(dir, @"Resources\withoutPassphrase.ppk");
			string withPassFileName = Path.Combine(dir, @"Resources\withPassphrase.ppk");
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
			

			string expectedPublicKeyAlgorithm = PpkFile.PublicKeyAlgorithms.ssh_rsa;
			string expectedWithoutPassPublicKeyString = 
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAqtfJwYLL9N6UyMYIrYoGu9eEZCIT3pS5OI0V" +
				"4t80baJDXPkdUBqkokcHoDjXKOy620c6MmFROBZ6AZHRvlGztefIT2+oVGJxR3TR" +
				"dPmQhhPzgyvsdWAzjQBIj7rZz5Dzu/sDOa2wm5PRHSMrk7G4f2b2/uaGuUvC+Ga5" +
				"aKXEDnc=";
			string expectedWithPassPublicKeyString = 
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAiQkGoRerOJfIN86YAzD+Yq76d/pM9p0TuKz1" +
				"8wDIrKiay/XWtqG6ErGL/W+XNOOd3AKL1XABzrC8xXc/zqkHbopQa207P+iFR6Va" +
				"cXSiiJm4KOg1VQiocoNB/j8dELzq0dJ6LsPD7qaGwkmNvvp5cWehcyOjIKHLa1JF" +
				"nwmdPLs=";
			string expectedWithoutPassComment = "without passphrase";
			string expectedWithPassComment = "with passphrase";
			string expectedWithoutPassPrivateKeyString =
				"AAAAgHyrTgnAT6TZxoSsL9iVJ4InpcyHkfVzcmeJjIL15/z53iFAKiWyk9BdWJeD" +
				"bJN8UQDg8x3YUAZVl01A5SoERN18aB7lgajejzJgQFOP5Ad7vA/83dFbrzAf10Ah" +
				"dbtaqHUdMwMWqdkqVa2EYCZ+O+0PeewHA3uBJECHlP/NN+GdAAAAQQDtQNlZb5AD" +
				"d9RthpU1X6+ePcR7POnz01GrUPRARzRB2h5JP+mwFnfjANSKhZhrzePpIL1jKYyI" +
				"o12b1qV/IXY5AAAAQQC4V5eZV62MzOuf1kdUVysFCVzt3mMLLcn57RQwRpqQfp5j" +
				"0r2JNiAFBYo4k/9phYYJ0FziDIz/MEvYMwXLCiovAAAAQQDMYEQojQraSZDbcUwy" +
				"OaEtSNGh9qtYIPuYilRFbiIU55Az5iujw8c7LCpNycSGeo6GGLAt6VCjp8v8abb0" +
				"wOqJ";
			string expectedWithPassDecryptedPrivateKeyString = 
				"AAAAgFF6/QXWuNWKrmZfKfQPSyXrgCuplYu3V9WXRiHJHV++MoccjYFZPjSg63QY" +
				"1nJ5gHT6mFVlMYHQ3vHz4MARegmAQ33bxTmwzRszLXua1W2hRgqCTDsG89MNe2Fn" +
				"iAaFjZcBP/eqXoknZdlnEbq7cV2A+qbLHxfVY0GZ3jvAzyx9AAAAQQDOrnDIH4x5" +
				"gJIKYn0Qfs2WYD9tioS11TnReWSzgmkeKILHhrCfPm4ZIkZNdGnC5wyuqh03HWSe" +
				"izsU7+hTbT0PAAAAQQCpvBtWZ0bFq8IKtxjfvMh0HEwrKpuYlj54M0cu8BED9xbl" +
				"8KNut/b5rY5aZD4TmY1IxiYii5+QvCqjSK9PAh2VAAAAQD1GlJSv/erLvQYO1nsL" +
				"aF2ooZ9Dg1m/NOnKDWJ8MOhMrLmqIxs6bKcKjVoEjgx5FqPI0pMwK0tpMH2slx92" +
				"JIM=";
			string expectedWithoutPassPrivateMACString = 
				"f7c9bf63097216304a05c1426ac9d42c4b3825cd";
			string oldFileFormatWithoutPassPrivateMACString = 
				"c39afc7d9ccb459900d7d9679e4d2cd564d8e0cc";
			string expectedWithPassPrivateMACString = 
				"8877acc44fa4306977f960fde25b20d7146019fb";


		

			/* test for successful constructor */
			target = new PpkFile(withPassFileName, getPassphrase, warnOldFileNotExpected);
			Assert.AreEqual(expectedWithPassComment, target.Key.Comment);
			
			/* read file to string for modification by subsequent tests */
			string withoutPassFileContents;
			byte[] modifiedFileContents;
			Stream stream = File.OpenRead(withoutPassFileName);
			StreamReader reader = new StreamReader(stream);
			withoutPassFileContents = reader.ReadToEnd();
			reader.Close();
			stream.Close();

			/* test bad file version */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("2", "3"));
			try {
				target = new PpkFile(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.FileVersion, ((PpkFileException)ex).Error);
			}

			/* test bad public key encryption algorithm */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("ssh-rsa", "xyz"));
			try {
				target = new PpkFile(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.PublicKeyEncryption, ((PpkFileException)ex).Error);
			}

			/* test bad private key encryption algorithm */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("none", "xyz"));
			try {
				target = new PpkFile(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.PrivateKeyEncryption, ((PpkFileException)ex).Error);
			}

			/* test bad file intgerity */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents.Replace("without", "with"));
			try {
				target = new PpkFile(modifiedFileContents, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.FileCorrupt, ((PpkFileException)ex).Error);
			}

			/* test bad passphrase */
			try {
				target = new PpkFile(withPassFileName, null, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.BadPassphrase, ((PpkFileException)ex).Error);
			}
			try {
				target = new PpkFile(withPassFileName, getBadPassphrase, warnOldFileNotExpected);
				Assert.Fail("Exception did not occur");
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.BadPassphrase, ((PpkFileException)ex).Error);
			}

			/* test old file format */
			modifiedFileContents = Encoding.UTF8.GetBytes(withoutPassFileContents
				.Replace("PuTTY-User-Key-File-2", "PuTTY-User-Key-File-1")
				.Replace("Private-MAC", "Private-Hash")
				.Replace(expectedWithoutPassPrivateMACString, oldFileFormatWithoutPassPrivateMACString));
			try {
				warnCallbackCalled = false;
				target = new PpkFile(modifiedFileContents, null, warnOldFileExpected);
				Assert.IsTrue(warnCallbackCalled);
			} catch (Exception ex) {
				Assert.Fail(ex.ToString());
			}

			/* test reading bad file */
			try {
				target = new PpkFile(emptyFileName, null, warnOldFileNotExpected);
			} catch (Exception ex) {
				Assert.IsInstanceOfType(ex, typeof(PpkFileException));
				Assert.AreEqual(PpkFileException.ErrorType.FileFormat, ((PpkFileException)ex).Error);
			}

		}

		/// <summary>
		///A test for GetPublicKey
		///</summary>
		[TestMethod()]
		public void GetPublicKeyTest()
		{
			byte[] data = Resources.withoutPassphrase_ppk;
			PpkFile.GetPassphraseCallback getPassphrase = null;
			PpkFile.WarnOldFileFormatCallback warnOldFileFormat = delegate() { };
			PpkFile target = new PpkFile(data, getPassphrase, warnOldFileFormat);
			AsymmetricAlgorithm alg = target.Key.Algorithm;
			byte[] expected = PSUtil.FromBase64(
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAqtfJwYLL9N6UyMYIrYoGu9eEZCIT3pS5OI0V" +
				"4t80baJDXPkdUBqkokcHoDjXKOy620c6MmFROBZ6AZHRvlGztefIT2+oVGJxR3TR" +
				"dPmQhhPzgyvsdWAzjQBIj7rZz5Dzu/sDOa2wm5PRHSMrk7G4f2b2/uaGuUvC+Ga5" +
				"aKXEDnc=");
			byte[] actual;
			actual = target.Key.GetSSH2PublicKeyBlob();
			Assert.AreEqual(expected.Length, actual.Length);
			for (int i=0; i < expected.Length; i++) {
				Assert.AreEqual(expected[0], actual[1]);
			}
		}
	}
}
