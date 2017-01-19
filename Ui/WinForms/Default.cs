﻿//
// Default.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013,2015 David Lechner
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

using System.Diagnostics;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
    /// <summary>
    /// Default implementation of delegate methods
    /// </summary>
    public static class Default
    {
        /**
        * MessageBox options for topmost and focus from:
        * https://msdn.microsoft.com/en-us/library/windows/desktop/ms645505(v=vs.85).aspx
        */
        private const MessageBoxOptions TopMost = (MessageBoxOptions)0x00040000;
        private const MessageBoxOptions SetForeground = (MessageBoxOptions)0x00010000;
        private const MessageBoxOptions SystemModal = (MessageBoxOptions)0x00001000;

        public static bool ConfirmCallback(ISshKey key, Process process)
        {
            var programName = Strings.askConfirmKeyUnknownProcess;
            if (process != null) {
                programName = string.Format("{0} ({1})", process.MainWindowTitle,
                    process.ProcessName);
            }

            DialogResult result = MessageBox.Show(
                string.Format(Strings.askConfirmKey, programName, key.Comment,
                key.GetMD5Fingerprint().ToHexString()), Util.AssemblyTitle,
                MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2, TopMost | SetForeground | SystemModal
            );
            return (result == DialogResult.Yes);
        }
    }
}
