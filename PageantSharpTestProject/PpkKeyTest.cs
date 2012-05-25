using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using PageantSharpTestProject.Properties;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

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
			byte[] rsaFileData = (byte[])Resources.ssh2_rsa_no_passphrase_ppk;
			PpkKey rsaTarget = PpkFile.ParseData(rsaFileData, delegate() { return null; }, delegate() { });
			string rsaExpectedFingerprint = "57:95:98:7f:c2:4e:98:1d:b9:5b:45:fe:6d:a4:6b:17";
			string rsaActual = PSUtil.ToHex(rsaTarget.GetFingerprint());
			Assert.AreEqual(rsaExpectedFingerprint, rsaActual);

			byte[] dsaFileData = (byte[])Resources.ssh2_dsa_no_passphrase_ppk;
			PpkKey dsaTarget = PpkFile.ParseData(dsaFileData, delegate() { return null; }, delegate() { });
			string dsaExpectedFingerprint = "4e:f1:fc:5d:80:5b:37:b6:13:67:ce:df:4e:83:7b:0b";
			string dsaActual = PSUtil.ToHex(dsaTarget.GetFingerprint());
			Assert.AreEqual(dsaExpectedFingerprint, dsaActual);
		}

		/// <summary>
		///A test for GetSSH2PublicKeyBlob
		///</summary>
		[TestMethod()]
		public void GetSSH2PublicKeyBlobTest()
		{
			byte[] data = Resources.ssh2_rsa_no_passphrase_ppk;
			PpkFile.GetPassphraseCallback getPassphrase = null;
			PpkFile.WarnOldFileFormatCallback warnOldFileFormat = delegate() { };
			PpkKey target = PpkFile.ParseData(data, getPassphrase, warnOldFileFormat);
		    AsymmetricCipherKeyPair	keyParam = target.KeyParameters;
			byte[] expected = PSUtil.FromBase64(
				"AAAAB3NzaC1yc2EAAAABJQAAAIEAhWqdEs/lz1r4L8ZAAS76rX7hj3rrI/6FNlBw" +
				"6ERba2VFmn2AHxQwZmHHmqM+UtiY57angjD9fTbTzL74C0+f/NrRY+BYXf1cF+u5" +
				"XmjNKygrsIq3yPMZV4q8YcN/ls9COcynOQMIEmJF6Q0LD7Gt9Uv5yjqc2Ay7VVhG" +
				"qZNnIeE=");
			byte[] actual;
			actual = target.GetSSH2PublicKeyBlob();
			Assert.AreEqual(expected.Length, actual.Length);
			for (int i=0; i < expected.Length; i++) {
				Assert.AreEqual(expected[0], actual[1]);
			}
		}
	}
}
