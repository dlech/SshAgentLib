using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Collections.Generic;
using PageantSharpTestProject.Properties;
using System.Security.Cryptography;

namespace PageantSharpTestProject
{

	/// <summary>
	///This is a test class for PageantWindowTest and is intended
	///to contain all PageantWindowTest Unit Tests
	///</summary>
	[TestClass()]
	public class PageantWindowTest
	{

		[DllImport("user32.dll")]
		public static extern IntPtr FindWindow(String sClassName, String sAppName);


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
		///A test for PageantWindow Constructor
		///</summary>
		[TestMethod()]
		public void PageantWindowConstructorTest()
		{
			// create new instance
			PageantWindow target = new PageantWindow(null);

			try {
				// emulate a client to make sure window is there
				IntPtr hwnd = FindWindow("Pageant", "Pageant");
				Assert.AreNotEqual(hwnd, IntPtr.Zero);

				// try starting a second instance, this should cause an exception
				Exception exception = null;
				try {
					PageantWindow target2 = new PageantWindow(null);
					target2.Dispose();
				} catch (Exception ex) {
					exception = ex;
				}
				Assert.IsInstanceOfType(exception, typeof(PageantException));
			} catch (Exception ex) {
				Assert.Fail(ex.ToString());
			} finally {
				// cleanup first instance
				target.Dispose();
			}
		}
		
		[TestMethod()]
		public void PageantWindowWndProcTest()
		{
			byte[] data = Resources.withoutPassphrase_ppk;
			PpkFile.GetPassphraseCallback getPassphrase = null;
			PpkFile.WarnOldFileFormatCallback warnOldFileFormat = delegate() { };
			PpkFile file = new PpkFile(ref data, getPassphrase, warnOldFileFormat);
			

			PageantWindow.GetSSH2KeysCallback getSSH2KeysCallback = delegate()
			{
				List<PpkKey> keyList = new List<PpkKey>();
				keyList.Add(file.Key);
				return keyList;
			};

			PageantWindow target = new PageantWindow(getSSH2KeysCallback);
			MessageBox.Show("Click OK when done");
			target.Dispose();
		}
	}
}
