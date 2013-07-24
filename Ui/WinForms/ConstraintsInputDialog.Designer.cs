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
      this.mLifetimeConstraintControl = new dlech.SshAgentLib.WinForms.LifetimeConstraintControl();
      this.mConfirmConstraintControl = new dlech.SshAgentLib.WinForms.ConfirmConstraintControl();
      this.SuspendLayout();
      // 
      // mOKButton
      // 
      this.mOKButton.Anchor = System.Windows.Forms.AnchorStyles.Bottom;
      this.mOKButton.Location = new System.Drawing.Point(51, 71);
      this.mOKButton.Name = "mOKButton";
      this.mOKButton.Size = new System.Drawing.Size(75, 23);
      this.mOKButton.TabIndex = 0;
      this.mOKButton.Text = "OK";
      this.mOKButton.UseVisualStyleBackColor = true;
      this.mOKButton.Click += new System.EventHandler(this.mOKButton_Click);
      // 
      // mLifetimeConstraintControl
      // 
      this.mLifetimeConstraintControl.AutoSize = true;
      this.mLifetimeConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mLifetimeConstraintControl.Checked = false;
      this.mLifetimeConstraintControl.Lifetime = ((uint)(600u));
      this.mLifetimeConstraintControl.Location = new System.Drawing.Point(12, 35);
      this.mLifetimeConstraintControl.Name = "mLifetimeConstraintControl";
      this.mLifetimeConstraintControl.Size = new System.Drawing.Size(158, 20);
      this.mLifetimeConstraintControl.TabIndex = 1;
      // 
      // mConfirmConstraintControl
      // 
      this.mConfirmConstraintControl.AutoSize = true;
      this.mConfirmConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mConfirmConstraintControl.BackColor = System.Drawing.Color.Transparent;
      this.mConfirmConstraintControl.Checked = false;
      this.mConfirmConstraintControl.Location = new System.Drawing.Point(12, 12);
      this.mConfirmConstraintControl.Name = "mConfirmConstraintControl";
      this.mConfirmConstraintControl.Size = new System.Drawing.Size(124, 17);
      this.mConfirmConstraintControl.TabIndex = 0;
      // 
      // ConstraintsInputDialog
      // 
      this.AcceptButton = this.mOKButton;
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(195, 106);
      this.ControlBox = false;
      this.Controls.Add(this.mLifetimeConstraintControl);
      this.Controls.Add(this.mConfirmConstraintControl);
      this.Controls.Add(this.mOKButton);
      this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
      this.MaximizeBox = false;
      this.MinimizeBox = false;
      this.Name = "ConstraintsInputDialog";
      this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
      this.Text = "Select Constraints";
      this.ResumeLayout(false);
      this.PerformLayout();

    }

    #endregion

    private System.Windows.Forms.Button mOKButton;
    private dlech.SshAgentLib.WinForms.ConfirmConstraintControl mConfirmConstraintControl;
    private dlech.SshAgentLib.WinForms.LifetimeConstraintControl mLifetimeConstraintControl;
  }
}