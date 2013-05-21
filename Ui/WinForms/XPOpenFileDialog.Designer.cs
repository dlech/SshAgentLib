namespace dlech.SshAgentLib.WinForms
{
  partial class XPOpenFileDialog
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

    #region Component Designer generated code

    /// <summary> 
    /// Required method for Designer support - do not modify 
    /// the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
      this.mConfirmConstraintControl = new KeeAgent.UI.ConfirmConstraintControl();
      this.mLifetimeConstraintControl = new KeeAgent.UI.LifetimeConstraintControl();
      this.mTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
      this.mTableLayoutPanel.SuspendLayout();
      this.SuspendLayout();
      // 
      // mConfirmConstraintControl
      // 
      this.mConfirmConstraintControl.Anchor = System.Windows.Forms.AnchorStyles.None;
      this.mConfirmConstraintControl.AutoSize = true;
      this.mConfirmConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mConfirmConstraintControl.BackColor = System.Drawing.Color.Transparent;
      this.mConfirmConstraintControl.Checked = false;
      this.mConfirmConstraintControl.Location = new System.Drawing.Point(217, 9);
      this.mConfirmConstraintControl.Name = "mConfirmConstraintControl";
      this.mConfirmConstraintControl.Size = new System.Drawing.Size(124, 17);
      this.mConfirmConstraintControl.TabIndex = 0;
      // 
      // mLifetimeConstraintControl
      // 
      this.mLifetimeConstraintControl.Anchor = System.Windows.Forms.AnchorStyles.None;
      this.mLifetimeConstraintControl.AutoSize = true;
      this.mLifetimeConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mLifetimeConstraintControl.Checked = false;
      this.mLifetimeConstraintControl.Lifetime = ((uint)(600u));
      this.mLifetimeConstraintControl.Location = new System.Drawing.Point(381, 4);
      this.mLifetimeConstraintControl.Name = "mLifetimeConstraintControl";
      this.mLifetimeConstraintControl.Size = new System.Drawing.Size(167, 26);
      this.mLifetimeConstraintControl.TabIndex = 1;
      // 
      // mTableLayoutPanel
      // 
      this.mTableLayoutPanel.ColumnCount = 4;
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 25F));
      this.mTableLayoutPanel.Controls.Add(this.mConfirmConstraintControl, 1, 0);
      this.mTableLayoutPanel.Controls.Add(this.mLifetimeConstraintControl, 2, 0);
      this.mTableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mTableLayoutPanel.Location = new System.Drawing.Point(0, 0);
      this.mTableLayoutPanel.Name = "mTableLayoutPanel";
      this.mTableLayoutPanel.RowCount = 1;
      this.mTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
      this.mTableLayoutPanel.Size = new System.Drawing.Size(746, 35);
      this.mTableLayoutPanel.TabIndex = 2;
      // 
      // XPOpenFileDialog
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.Controls.Add(this.mTableLayoutPanel);
      this.Name = "XPOpenFileDialog";
      this.Size = new System.Drawing.Size(746, 35);
      this.mTableLayoutPanel.ResumeLayout(false);
      this.mTableLayoutPanel.PerformLayout();
      this.ResumeLayout(false);

    }

    #endregion

    private KeeAgent.UI.ConfirmConstraintControl mConfirmConstraintControl;
    private KeeAgent.UI.LifetimeConstraintControl mLifetimeConstraintControl;
    private System.Windows.Forms.TableLayoutPanel mTableLayoutPanel;
  }
}
