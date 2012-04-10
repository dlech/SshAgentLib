using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using PageantSharpTestProject.Properties;
using System.Security.Cryptography;

namespace PageantSharpTestProject
{
    
    
    /// <summary>
    ///This is a test class for PpkKeyTest and is intended
    ///to contain all PpkKeyTest Unit Tests
    ///</summary>
	[TestClass()]
	public class PpkKeyTest
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
		///A test for GetFingerprint
		///</summary>
		[TestMethod()]
		public void GetFingerprintTest()
		{
			byte[] fileData = (byte[])Resources.withoutPassphrase_ppk;
			PpkKey target = PpkFile.ParseData(fileData, delegate() { return null; }, delegate() { });
			string expected = "2d:72:cf:ea:66:44:6c:42:d7:78:84:e7:c2:c6:7b:b5";
			string actual;
			actual = PSUtil.ToHex(target.GetFingerprint());
			Assert.AreEqual(expected, actual);
		}

		/// <summary>
		///A test for GetSSH2PublicKeyBlob
		///</summary>
		[TestMethod()]
		public void GetSSH2PublicKeyBlobTest()
		{
			byte[] data = Resources.withoutPassphrase_ppk;
			PpkFile.GetPassphraseCallback getPassphrase = null;
			PpkFile.WarnOldFileFormatCallback warnOldFileFormat = delegate() { };
			PpkKey target = PpkFile.ParseData(data, getPassphrase, warnOldFileFormat);
			AsymmetricAlgorithm alg = target.Algorithm;
			byte[] expected = PSUtil.FromBase64(
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAqtfJwYLL9N6UyMYIrYoGu9eEZCIT3pS5OI0V" +
				"4t80baJDXPkdUBqkokcHoDjXKOy620c6MmFROBZ6AZHRvlGztefIT2+oVGJxR3TR" +
				"dPmQhhPzgyvsdWAzjQBIj7rZz5Dzu/sDOa2wm5PRHSMrk7G4f2b2/uaGuUvC+Ga5" +
				"aKXEDnc=");
			byte[] actual;
			actual = target.GetSSH2PublicKeyBlob();
			Assert.AreEqual(expected.Length, actual.Length);
			for (int i=0; i < expected.Length; i++) {
				Assert.AreEqual(expected[0], actual[1]);
			}
		}
	}
}
