namespace KeeAgent.UI
{
  partial class ConfirmConstraintControl
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
      this.mConfirmCheckBox = new System.Windows.Forms.CheckBox();
      this.SuspendLayout();
      // 
      // mConfirmCheckBox
      // 
      this.mConfirmCheckBox.AutoSize = true;
      this.mConfirmCheckBox.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mConfirmCheckBox.Location = new System.Drawing.Point(0, 0);
      this.mConfirmCheckBox.Name = "mConfirmCheckBox";
      this.mConfirmCheckBox.Size = new System.Drawing.Size(124, 17);
      this.mConfirmCheckBox.TabIndex = 0;
      this.mConfirmCheckBox.Text = "Require Confirmation";
      this.mConfirmCheckBox.UseVisualStyleBackColor = true;
      // 
      // ConfirmConstraintControl
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.AutoSize = true;
      this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.Controls.Add(this.mConfirmCheckBox);
      this.Name = "ConfirmConstraintControl";
      this.Size = new System.Drawing.Size(124, 17);
      this.ResumeLayout(false);
      this.PerformLayout();

    }

    #endregion

    private System.Windows.Forms.CheckBox mConfirmCheckBox;
  }
}
