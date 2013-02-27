namespace dlech.SshAgentLib.WinForms
{
  partial class KeyManagerForm
  {
    /// <summary>
    /// Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    /// Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
    protected override void Dispose(bool disposing)
    {
      if (disposing && (components != null)) {
        components.Dispose();
      }
      base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    /// Required method for Designer support - do not modify
    /// the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
      this.mainTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
      this.keyInfoViewer = new dlech.SshAgentLib.WinForms.KeyInfoView();
      this.mainTableLayoutPanel.SuspendLayout();
      this.SuspendLayout();
      // 
      // mainTableLayoutPanel
      // 
      this.mainTableLayoutPanel.ColumnCount = 1;
      this.mainTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
      this.mainTableLayoutPanel.Controls.Add(this.keyInfoViewer, 0, 0);
      this.mainTableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mainTableLayoutPanel.Location = new System.Drawing.Point(0, 0);
      this.mainTableLayoutPanel.Name = "mainTableLayoutPanel";
      this.mainTableLayoutPanel.RowCount = 2;
      this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
      this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
      this.mainTableLayoutPanel.Size = new System.Drawing.Size(604, 211);
      this.mainTableLayoutPanel.TabIndex = 7;
      // 
      // keyInfoViewer
      // 
      this.keyInfoViewer.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
      this.keyInfoViewer.AutoSize = true;
      this.keyInfoViewer.Location = new System.Drawing.Point(3, 3);
      this.keyInfoViewer.Name = "keyInfoViewer";
      this.keyInfoViewer.Size = new System.Drawing.Size(598, 205);
      this.keyInfoViewer.TabIndex = 0;
      // 
      // KeyManagerForm
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(604, 211);
      this.Controls.Add(this.mainTableLayoutPanel);
      this.Name = "KeyManagerForm";
      this.Text = "SSH Agent";
      this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MainForm_FormClosing);
      this.Load += new System.EventHandler(this.MainForm_Load);
      this.mainTableLayoutPanel.ResumeLayout(false);
      this.mainTableLayoutPanel.PerformLayout();
      this.ResumeLayout(false);

    }

    #endregion

    private WinForms.KeyInfoView keyInfoViewer;
    private System.Windows.Forms.TableLayoutPanel mainTableLayoutPanel;
  }
}

