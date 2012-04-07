using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace PageantSharpTestProject
{
    
    
    /// <summary>
    ///This is a test class for PSUtilTest and is intended
    ///to contain all PSUtilTest Unit Tests
    ///</summary>
	[TestClass()]
	public class PSUtilTest
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
		///A test for TrimLeadingZero
		///</summary>
		[TestMethod()]
		public void TrimLeadingZeroTest()
		{
			PinnedByteArray array1 = new PinnedByteArray(new byte[] { 1, 2, 3, 4 });
			PSUtil.TrimLeadingZero(array1);
			Assert.AreEqual(4, array1.Data.Length);

			PinnedByteArray array2 = new PinnedByteArray(new byte[] { 0, 1, 2, 3, 4 });
			PSUtil.TrimLeadingZero(array2);
			Assert.AreEqual(4, array2.Data.Length);
		}
	}
}
