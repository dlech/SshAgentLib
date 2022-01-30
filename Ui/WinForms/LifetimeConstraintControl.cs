//
// LifetimeConstraintControl.cs
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
using System.ComponentModel;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
    public partial class LifetimeConstraintControl : UserControl
    {
        public bool Checked
        {
            get { return mLifetimeCheckBox.Checked; }
            set { mLifetimeCheckBox.Checked = value; }
        }

        /// <summary>
        /// returns the lifetime entered in the text box or 0 if entered value is invalid
        /// </summary>
        public uint Lifetime
        {
            get
            {
                uint lifetime;
                if (uint.TryParse(mLifetimeTextBox.Text, out lifetime))
                {
                    return lifetime;
                }
                return 0;
            }
            set { mLifetimeTextBox.Text = value.ToString(); }
        }

        public LifetimeConstraintControl()
        {
            InitializeComponent();
            if (Type.GetType("Mono.Runtime") != null)
            {
                AutoSize = false;
                Width = 250;
            }
        }

        private void mLifetimeCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            mLifetimeTextBox.Enabled = mLifetimeCheckBox.Checked;
            mTimeUnitsLabel.Enabled = mLifetimeCheckBox.Checked;
            if (mLifetimeCheckBox.Checked)
            {
                mLifetimeTextBox.SelectAll();
                mLifetimeTextBox.Focus();
            }
        }

        private void mLifetimeTextBox_Validating(object sender, CancelEventArgs e)
        {
            uint testValue = 0;
            if (string.IsNullOrWhiteSpace(mLifetimeTextBox.Text))
            {
                mLifetimeTextBox.Text = "0";
            }
            if (!uint.TryParse(mLifetimeTextBox.Text, out testValue))
            {
                MessageBox.Show(
                    "Invalid lifetime.",
                    Util.AssemblyTitle,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
                e.Cancel = true;
            }
        }
    }
}
