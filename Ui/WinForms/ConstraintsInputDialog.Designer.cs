namespace dlech.SshAgentLib.WinForms
{
  partial class ConstraintsInputDialog
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
      this.mOKButton = new System.Windows.Forms.Button();
      this.mTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
      this.mConfirmConstraintControl = new KeeAgent.UI.ConfirmConstraintControl();
      this.mLifetimeConstraintControl = new KeeAgent.UI.LifetimeConstraintControl();
      this.mTableLayoutPanel.SuspendLayout();
      this.SuspendLayout();
      // 
      // mOKButton
      // 
      this.mOKButton.Anchor = System.Windows.Forms.AnchorStyles.Bottom;
      this.mOKButton.Location = new System.Drawing.Point(64, 89);
      this.mOKButton.Name = "mOKButton";
      this.mOKButton.Size = new System.Drawing.Size(75, 23);
      this.mOKButton.TabIndex = 0;
      this.mOKButton.Text = "OK";
      this.mOKButton.UseVisualStyleBackColor = true;
      this.mOKButton.Click += new System.EventHandler(this.mOKButton_Click);
      // 
      // mTableLayoutPanel
      // 
      this.mTableLayoutPanel.ColumnCount = 1;
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
      this.mTableLayoutPanel.Controls.Add(this.mConfirmConstraintControl, 0, 0);
      this.mTableLayoutPanel.Controls.Add(this.mLifetimeConstraintControl, 0, 1);
      this.mTableLayoutPanel.Location = new System.Drawing.Point(12, 7);
      this.mTableLayoutPanel.Name = "mTableLayoutPanel";
      this.mTableLayoutPanel.RowCount = 2;
      this.mTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
      this.mTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
      this.mTableLayoutPanel.Size = new System.Drawing.Size(194, 68);
      this.mTableLayoutPanel.TabIndex = 1;
      // 
      // mConfirmConstraintControl
      // 
      this.mConfirmConstraintControl.Anchor = System.Windows.Forms.AnchorStyles.Left;
      this.mConfirmConstraintControl.AutoSize = true;
      this.mConfirmConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mConfirmConstraintControl.BackColor = System.Drawing.Color.Transparent;
      this.mConfirmConstraintControl.Checked = false;
      this.mConfirmConstraintControl.Location = new System.Drawing.Point(3, 8);
      this.mConfirmConstraintControl.Name = "mConfirmConstraintControl";
      this.mConfirmConstraintControl.Size = new System.Drawing.Size(124, 17);
      this.mConfirmConstraintControl.TabIndex = 0;
      // 
      // mLifetimeConstraintControl
      // 
      this.mLifetimeConstraintControl.Anchor = System.Windows.Forms.AnchorStyles.Left;
      this.mLifetimeConstraintControl.AutoSize = true;
      this.mLifetimeConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mLifetimeConstraintControl.Checked = false;
      this.mLifetimeConstraintControl.Lifetime = ((uint)(600u));
      this.mLifetimeConstraintControl.Location = new System.Drawing.Point(3, 41);
      this.mLifetimeConstraintControl.Name = "mLifetimeConstraintControl";
      this.mLifetimeConstraintControl.Size = new System.Drawing.Size(158, 20);
      this.mLifetimeConstraintControl.TabIndex = 1;
      // 
      // ConstraintsInputDialog
      // 
      this.AcceptButton = this.mOKButton;
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(206, 124);
      this.ControlBox = false;
      this.Controls.Add(this.mTableLayoutPanel);
      this.Controls.Add(this.mOKButton);
      this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
      this.MaximizeBox = false;
      this.MinimizeBox = false;
      this.Name = "ConstraintsInputDialog";
      this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
      this.Text = "Select Constraints";
      this.mTableLayoutPanel.ResumeLayout(false);
      this.mTableLayoutPanel.PerformLayout();
      this.ResumeLayout(false);

    }

    #endregion

    private System.Windows.Forms.Button mOKButton;
    private System.Windows.Forms.TableLayoutPanel mTableLayoutPanel;
    private KeeAgent.UI.ConfirmConstraintControl mConfirmConstraintControl;
    private KeeAgent.UI.LifetimeConstraintControl mLifetimeConstraintControl;
  }
}