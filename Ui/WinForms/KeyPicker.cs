//
// KeyInfoView.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2015 David Lechner
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
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace dlech.SshAgentLib.WinForms
{
  public partial class KeyPicker : Form
  {
    public IEnumerable<ISshKey> SelectedKeys
    {
      get
      {
        return keyDataGridView.SelectedRows.Cast<DataGridViewRow>()
          .Select(r => ((KeyWrapper)r.DataBoundItem).GetKey());
      }
    }

    public KeyPicker(ICollection<ISshKey> keys)
    {
      if (keys == null) {
        throw new ArgumentNullException("keys");
      }
      if (keys.Count == 0) {
        throw new ArgumentException("No keys in list.", "keys");
      }
      InitializeComponent();
      keyDataGridView.ColumnAdded += keyDataGridView_ColumnAdded;
      keyDataGridView.DataSource = keys.Select(k => new KeyWrapper(k)).ToList();
      keyDataGridView.Rows[0].Selected = true;
    }

    void keyDataGridView_ColumnAdded(object sender, DataGridViewColumnEventArgs e)
    {
      e.Column.AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells;
      if (e.Column.DataPropertyName == "Confirm" || e.Column.DataPropertyName == "Lifetime") {
        e.Column.Visible = false;
      }
    }

    private void keyDataGridView_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
    {
      keyDataGridView.Rows[e.RowIndex].Selected = true;
      AcceptButton.PerformClick();
    }
  }
}
