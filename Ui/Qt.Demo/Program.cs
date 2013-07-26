//
// Program.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using QtGui;
using QtCore;
using dlech.SshAgentLib;
using System.Diagnostics;

namespace dlech.SshAgentLib.Ui.QtAgent
{
  public class Program : QDialog
  {

    public Program ()
    {
      WindowTitle = Tr("SSH Key Manager");
      SizeGripEnabled = true;

      var keyManager = new KeyManagerFrame ();
      keyManager.SetAgent (new UnixAgent ());
      var layout = new QVBoxLayout ();
      layout.AddWidget (keyManager);
      layout.ContentsMargins = new QMargins (0, 0, 0, 0);
      Layout = layout;

      Show ();
    }

    [STAThread]
    public static int Main(String[] args)
    {
      if (Environment.OSVersion.Platform == PlatformID.Unix ||
          Environment.OSVersion.Platform == PlatformID.MacOSX)
      {
        Environment.SetEnvironmentVariable("LD_LIBRARY_PATH",
                                           Environment.CurrentDirectory);
      }
      new QApplication (args);
      new Program ();
      return QApplication.Exec ();
    }

  }
}
