using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Diagnostics;
using System.IO;
using PageantSharpTestProject.Properties;
using System.Text;

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
		public void PpkFileConstructorFromFileTest()
		{
			Assembly asm = Assembly.GetExecutingAssembly();
			string dir = Path.GetDirectoryName(asm.Location);
			string fileName = Path.Combine(dir, @"Resources\withoutPassphrase.ppk");
			try {
				PpkFile target = new PpkFile(fileName);
				Assert.AreEqual("ssh-rsa", target.PublicKeyAlgorithm);
				Assert.AreEqual("none", target.PrivateKeyAlgorithm);
				Assert.AreEqual("without passphrase", target.Comment);
				Assert.AreEqual("AAAAB3NzaC1yc2EAAAABJQAAAIEAqtfJwYLL9N6UyMYIrYoGu9eEZCIT3pS5OI0V" +
												"4t80baJDXPkdUBqkokcHoDjXKOy620c6MmFROBZ6AZHRvlGztefIT2+oVGJxR3TR" +
												"dPmQhhPzgyvsdWAzjQBIj7rZz5Dzu/sDOa2wm5PRHSMrk7G4f2b2/uaGuUvC+Ga5" +
												"aKXEDnc=", target.PublicKeyString);
				Assert.AreEqual("AAAAgHyrTgnAT6TZxoSsL9iVJ4InpcyHkfVzcmeJjIL15/z53iFAKiWyk9BdWJeD" +
												"bJN8UQDg8x3YUAZVl01A5SoERN18aB7lgajejzJgQFOP5Ad7vA/83dFbrzAf10Ah" +
												"dbtaqHUdMwMWqdkqVa2EYCZ+O+0PeewHA3uBJECHlP/NN+GdAAAAQQDtQNlZb5AD" +
												"d9RthpU1X6+ePcR7POnz01GrUPRARzRB2h5JP+mwFnfjANSKhZhrzePpIL1jKYyI" +
												"o12b1qV/IXY5AAAAQQC4V5eZV62MzOuf1kdUVysFCVzt3mMLLcn57RQwRpqQfp5j" +
												"0r2JNiAFBYo4k/9phYYJ0FziDIz/MEvYMwXLCiovAAAAQQDMYEQojQraSZDbcUwy" +
												"OaEtSNGh9qtYIPuYilRFbiIU55Az5iujw8c7LCpNycSGeo6GGLAt6VCjp8v8abb0" +
												"wOqJ", target.PrivateKeyString);
				Assert.AreEqual("f7c9bf63097216304a05c1426ac9d42c4b3825cd", target.PrivateMACString);
				Assert.IsTrue(target.IsMAC);
			} catch (Exception ex) {
				Assert.Fail(ex.ToString());
			}

		}

		/// <summary>
		///A test for PpkFile Constructor
		///</summary>
		[TestMethod()]
		public void PpkFileConstructorFromDataTest()
		{
			byte[] data = Resources.withoutPassphrase_ppk;
			PpkFile target = new PpkFile(data);
		}

		/// <summary>
		///A test for DecryptPrivateKey
		///</summary>
		[TestMethod()]
		public void DecryptPrivateKeyTest()
		{
			Assembly asm = Assembly.GetExecutingAssembly();
			string dir = Path.GetDirectoryName(asm.Location);
			string fileName = Path.Combine(dir, @"Resources\withPassphrase.ppk");
			PpkFile target = new PpkFile(fileName);
			string passphrase = "PageantSharp";
			byte[] expected = PSUtil.FromBase64(
				"AAAAgFF6/QXWuNWKrmZfKfQPSyXrgCuplYu3V9WXRiHJHV++MoccjYFZPjSg63QY" +
				"1nJ5gHT6mFVlMYHQ3vHz4MARegmAQ33bxTmwzRszLXua1W2hRgqCTDsG89MNe2Fn" +
				"iAaFjZcBP/eqXoknZdlnEbq7cV2A+qbLHxfVY0GZ3jvAzyx9AAAAQQDOrnDIH4x5" +
				"gJIKYn0Qfs2WYD9tioS11TnReWSzgmkeKILHhrCfPm4ZIkZNdGnC5wyuqh03HWSe" +
				"izsU7+hTbT0PAAAAQQCpvBtWZ0bFq8IKtxjfvMh0HEwrKpuYlj54M0cu8BED9xbl" +
				"8KNut/b5rY5aZD4TmY1IxiYii5+QvCqjSK9PAh2VAAAAQD1GlJSv/erLvQYO1nsL" +
				"aF2ooZ9Dg1m/NOnKDWJ8MOhMrLmqIxs6bKcKjVoEjgx5FqPI0pMwK0tpMH2slx92" +
				"JIM=");
			byte[] actual;
			actual = target.DecryptPrivateKey(passphrase);
			for (int i = 0; i < expected.Length; i++) {
				Assert.AreEqual(expected[i], actual[i]);
			}
		}
	}
}
