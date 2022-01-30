//
// ConstraintInputDialog.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2013-2014 David Lechner
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
using System.Drawing;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
    public partial class ConstraintsInputDialog : Form
    {
        public bool ConfirmConstraintChecked
        {
            get { return confirmConstraintControl.Checked; }
        }

        public bool LifetimeConstraintChecked
        {
            get { return lifetimeConstraintControl.Checked; }
        }

        public uint LifetimeDuration
        {
            get { return lifetimeConstraintControl.Lifetime; }
        }

        public ConstraintsInputDialog() : this(false) { }

        public ConstraintsInputDialog(bool initalConfirmChecked)
        {
            InitializeComponent();
            confirmConstraintControl.Checked = initalConfirmChecked;
            if (Type.GetType("Mono.Runtime") != null)
            {
                confirmConstraintControl.AutoSize = false;
                confirmConstraintControl.Size = new Size(200, confirmConstraintControl.Height);
                lifetimeConstraintControl.AutoSize = false;
                lifetimeConstraintControl.Size = new Size(200, lifetimeConstraintControl.Height);
                okButton.Location = new Point(okButton.Location.X, okButton.Location.Y - 20);
                Size = new Size(Width, Height + 20);
            }
        }

        private void mOKButton_Click(object sender, EventArgs e)
        {
            if (LifetimeConstraintChecked && LifetimeDuration == 0)
            {
                MessageBox.Show(
                    "Invalid Lifetime",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Exclamation
                );
            }
            else
            {
                DialogResult = DialogResult.OK;
                Close();
            }
        }
    }
}
