using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using PageantSharpTestProject.Properties;

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
			byte[] fileData = (byte[])Resources.withoutPassphrase_ppk.Clone();
			PpkFile file = new PpkFile(ref fileData, delegate() { return null; }, delegate() { });
			PpkKey target = file.Key;
			string expected = "2d:72:cf:ea:66:44:6c:42:d7:78:84:e7:c2:c6:7b:b5";
			string actual;
			actual = PSUtil.ToHex(target.GetFingerprint(),":");
			Assert.AreEqual(expected, actual);
		}
	}
}
