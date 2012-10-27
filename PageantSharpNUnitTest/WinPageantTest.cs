using dlech.PageantSharp;
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using NUnit.Framework;
using PageantSharpNUnitTest.Properties;

namespace PageantSharpTest
{

  /// <summary>
  ///This is a test class for PageantWindowTest and is intended
  ///to contain all PageantWindowTest Unit Tests
  ///</summary>
  [TestFixture()]
#if __MonoCS__
  [Ignore("Mono")]
#endif
  public class WinPageantTest 
  {

    [DllImport("user32.dll")]
    public static extern IntPtr FindWindow(String sClassName, String sAppName);

    /// <summary>
    ///A test for PageantWindow Constructor
    ///</summary>
    [Test()]
    public void PageantWindowConstructorTest()
    {
      // create new instance
      Agent.CallBacks callbacks = new Agent.CallBacks();
      WinPageant target = new WinPageant(callbacks);

      try {
        // emulate a client to make sure window is there
        IntPtr hwnd = FindWindow("Pageant", "Pageant");
        Assert.AreNotEqual(hwnd, IntPtr.Zero);

        // try starting a second instance
        Assert.Throws<PageantRunningException>(delegate()
        {
          WinPageant target2 = new WinPageant(callbacks);
          target2.Dispose();
        });        
      } catch (Exception ex) {
        Assert.Fail(ex.ToString());
      } finally {
        // cleanup first instance
        target.Dispose();
      }
    }

    [Test()]
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
          byte[] curFingerprint = OpenSsh.GetFingerprint(key.CipherKeyPair);
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

      Agent.AddSSH2KeyCallback addSS2KeyCallback = delegate(PpkKey key)
      {
        return true;
      };

      Agent.CallBacks callbacks = new Agent.CallBacks();
      callbacks.getSSH2KeyList = getSSH2KeysCallback;
      callbacks.getSSH2Key = getSSH2KeyCallback;
      callbacks.addSSH2Key = addSS2KeyCallback;
      WinPageant target = new WinPageant(callbacks);
      MessageBox.Show("Click OK when done");
      target.Dispose();
    }
  
  }
}
