using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Collections.ObjectModel;
using dlech.SshAgentLib;
using System.Runtime.Serialization;
using System.Diagnostics;
using System.IO;

namespace dlech.SshAgentLib.WinForms
{
  public partial class KeyManagerForm : Form
  {
    public KeyManagerForm(IAgent aAgent)
    {
      InitializeComponent();
      keyInfoViewer.SetAgent(aAgent); 
    }

    private void MainForm_Load(object sender, EventArgs e)
    {
           
    }

    private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
    {
      //Properties.Settings.Default.Save();      
    }
  }
}
