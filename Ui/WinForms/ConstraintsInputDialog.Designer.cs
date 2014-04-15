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
      this.okButton = new System.Windows.Forms.Button();
      this.lifetimeConstraintControl = new dlech.SshAgentLib.WinForms.LifetimeConstraintControl();
      this.confirmConstraintControl = new dlech.SshAgentLib.WinForms.ConfirmConstraintControl();
      this.SuspendLayout();
      // 
      // mOKButton
      // 
      this.okButton.Anchor = System.Windows.Forms.AnchorStyles.Bottom;
      this.okButton.Location = new System.Drawing.Point(51, 71);
      this.okButton.Name = "mOKButton";
      this.okButton.Size = new System.Drawing.Size(75, 23);
      this.okButton.TabIndex = 0;
      this.okButton.Text = "OK";
      this.okButton.UseVisualStyleBackColor = true;
      this.okButton.Click += new System.EventHandler(this.mOKButton_Click);
      // 
      // mLifetimeConstraintControl
      // 
      this.lifetimeConstraintControl.AutoSize = true;
      this.lifetimeConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.lifetimeConstraintControl.Checked = false;
      this.lifetimeConstraintControl.Lifetime = ((uint)(600u));
      this.lifetimeConstraintControl.Location = new System.Drawing.Point(12, 35);
      this.lifetimeConstraintControl.Name = "mLifetimeConstraintControl";
      this.lifetimeConstraintControl.Size = new System.Drawing.Size(158, 20);
      this.lifetimeConstraintControl.TabIndex = 1;
      // 
      // mConfirmConstraintControl
      // 
      this.confirmConstraintControl.AutoSize = true;
      this.confirmConstraintControl.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.confirmConstraintControl.BackColor = System.Drawing.Color.Transparent;
      this.confirmConstraintControl.Checked = false;
      this.confirmConstraintControl.Location = new System.Drawing.Point(12, 12);
      this.confirmConstraintControl.Name = "mConfirmConstraintControl";
      this.confirmConstraintControl.Size = new System.Drawing.Size(124, 17);
      this.confirmConstraintControl.TabIndex = 0;
      // 
      // ConstraintsInputDialog
      // 
      this.AcceptButton = this.okButton;
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(195, 106);
      this.ControlBox = false;
      this.Controls.Add(this.lifetimeConstraintControl);
      this.Controls.Add(this.confirmConstraintControl);
      this.Controls.Add(this.okButton);
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

    private System.Windows.Forms.Button okButton;
    private dlech.SshAgentLib.WinForms.ConfirmConstraintControl confirmConstraintControl;
    private dlech.SshAgentLib.WinForms.LifetimeConstraintControl lifetimeConstraintControl;
  }
}