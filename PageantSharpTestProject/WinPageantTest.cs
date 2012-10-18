using dlech.PageantSharp;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Collections.Generic;
using PageantSharpTestProject.Properties;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace PageantSharpTestProject
{

    /// <summary>
    ///This is a test class for PageantWindowTest and is intended
    ///to contain all PageantWindowTest Unit Tests
    ///</summary>
    [TestClass()]
    public class WinPageantTest
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
            WinPageant target = new WinPageant(null, null);

            try {
                // emulate a client to make sure window is there
                IntPtr hwnd = FindWindow("Pageant", "Pageant");
                Assert.AreNotEqual(hwnd, IntPtr.Zero);

                // try starting a second instance, this should cause an exception
                Exception exception = null;
                try {
                    WinPageant target2 = new WinPageant(null, null);
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
            byte[] data = Resources.ssh2_rsa_no_passphrase_ppk;
            PpkFile.GetPassphraseCallback getPassphrase = null;
            PpkFile.WarnOldFileFormatCallback warnOldFileFormat = delegate() { };
            PpkKey keyFromData = PpkFile.ParseData(data, getPassphrase, warnOldFileFormat);

            List<PpkKey> keyList = new List<PpkKey>();
            keyList.Add(keyFromData);

            Agent.GetSSH2KeyListCallback getSSH2KeysCallback = delegate()
            {
                return keyList;
            };

            Agent.GetSSH2KeyCallback getSSH2KeyCallback = delegate(byte[] reqFingerprint)
            {
                foreach (PpkKey key in keyList) {
                    byte[] curFingerprint = key.GetFingerprint();
                    if (curFingerprint.Length == reqFingerprint.Length) {
                        for (int i = 0; i < curFingerprint.Length; i++) {
                            if (curFingerprint[i] != reqFingerprint[i]) {
                                break;
                            }
                            if (i == curFingerprint.Length - 1) {
                                return key;
                            }
                        }
                    }
                }
                return null;
            };

            WinPageant target = new WinPageant(getSSH2KeysCallback, getSSH2KeyCallback);
            MessageBox.Show("Click OK when done");
            target.Dispose();
        }

        [TestMethod()]
        public void TestDsaSig()
        {
            DSA dsa1 = DSA.Create();
            DSAParameters dsa1params = dsa1.ExportParameters(true);

            DsaParameters dsa2common = new DsaParameters(
                new BigInteger(1, dsa1params.P),
                new BigInteger(1, dsa1params.Q),
                new BigInteger(1, dsa1params.G));
            DsaPublicKeyParameters dsa2public = new DsaPublicKeyParameters(
                new BigInteger(1, dsa1params.Y), dsa2common);
            DsaPrivateKeyParameters dsa2private = new DsaPrivateKeyParameters(
                new BigInteger(1, dsa1params.X), dsa2common);

            byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            SHA1 sha = SHA1.Create();
            sha.ComputeHash(data);
            byte[] dsa1result = dsa1.CreateSignature(sha.Hash);

            ISigner dsa2signer = SignerUtilities.GetSigner("SHA-1withDSA");
            //algName = PpkFile.PublicKeyAlgorithms.ssh_dss;

            dsa2signer.Init(true, dsa2private);
            dsa2signer.BlockUpdate(data, 0, data.Length);
            byte[] dsa2result = dsa2signer.GenerateSignature();

            Assert.IsTrue(dsa1.VerifySignature(sha.Hash, dsa2result));

            dsa2signer.Init(false, dsa2public);
            dsa2signer.BlockUpdate(data, 0, data.Length);

            Assert.IsTrue(dsa2signer.VerifySignature(dsa1result));

        }
    }
}
