namespace dlech.SshAgentLib.WinForms
{
  partial class LifetimeConstraintControl
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
      this.mTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
      this.mLifetimeCheckBox = new System.Windows.Forms.CheckBox();
      this.mLifetimeTextBox = new System.Windows.Forms.TextBox();
      this.mTimeUnitsLabel = new System.Windows.Forms.Label();
      this.mTableLayoutPanel.SuspendLayout();
      this.SuspendLayout();
      // 
      // mTableLayoutPanel
      // 
      this.mTableLayoutPanel.AutoSize = true;
      this.mTableLayoutPanel.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.mTableLayoutPanel.ColumnCount = 3;
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
      this.mTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
      this.mTableLayoutPanel.Controls.Add(this.mLifetimeCheckBox, 0, 0);
      this.mTableLayoutPanel.Controls.Add(this.mLifetimeTextBox, 1, 0);
      this.mTableLayoutPanel.Controls.Add(this.mTimeUnitsLabel, 2, 0);
      this.mTableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mTableLayoutPanel.GrowStyle = System.Windows.Forms.TableLayoutPanelGrowStyle.FixedSize;
      this.mTableLayoutPanel.Location = new System.Drawing.Point(0, 0);
      this.mTableLayoutPanel.Name = "mTableLayoutPanel";
      this.mTableLayoutPanel.RowCount = 1;
      this.mTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
      this.mTableLayoutPanel.Size = new System.Drawing.Size(158, 20);
      this.mTableLayoutPanel.TabIndex = 0;
      // 
      // mLifetimeCheckBox
      // 
      this.mLifetimeCheckBox.AutoSize = true;
      this.mLifetimeCheckBox.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mLifetimeCheckBox.Location = new System.Drawing.Point(0, 0);
      this.mLifetimeCheckBox.Margin = new System.Windows.Forms.Padding(0);
      this.mLifetimeCheckBox.Name = "mLifetimeCheckBox";
      this.mLifetimeCheckBox.Size = new System.Drawing.Size(62, 20);
      this.mLifetimeCheckBox.TabIndex = 0;
      this.mLifetimeCheckBox.Text = "Lifetime";
      this.mLifetimeCheckBox.UseVisualStyleBackColor = true;
      this.mLifetimeCheckBox.CheckedChanged += new System.EventHandler(this.mLifetimeCheckBox_CheckedChanged);
      // 
      // mLifetimeTextBox
      // 
      this.mLifetimeTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mLifetimeTextBox.Enabled = false;
      this.mLifetimeTextBox.Location = new System.Drawing.Point(65, 0);
      this.mLifetimeTextBox.Margin = new System.Windows.Forms.Padding(3, 0, 3, 0);
      this.mLifetimeTextBox.Name = "mLifetimeTextBox";
      this.mLifetimeTextBox.Size = new System.Drawing.Size(38, 20);
      this.mLifetimeTextBox.TabIndex = 1;
      this.mLifetimeTextBox.Text = "600";
      this.mLifetimeTextBox.Validating += new System.ComponentModel.CancelEventHandler(this.mLifetimeTextBox_Validating);
      // 
      // mTimeUnitsLabel
      // 
      this.mTimeUnitsLabel.AutoSize = true;
      this.mTimeUnitsLabel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mTimeUnitsLabel.Enabled = false;
      this.mTimeUnitsLabel.Location = new System.Drawing.Point(109, 0);
      this.mTimeUnitsLabel.Margin = new System.Windows.Forms.Padding(3, 0, 0, 0);
      this.mTimeUnitsLabel.Name = "mTimeUnitsLabel";
      this.mTimeUnitsLabel.Size = new System.Drawing.Size(49, 20);
      this.mTimeUnitsLabel.TabIndex = 2;
      this.mTimeUnitsLabel.Text = "Seconds";
      this.mTimeUnitsLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
      // 
      // LifetimeConstraintControl
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.AutoSize = true;
      this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
      this.Controls.Add(this.mTableLayoutPanel);
      this.Name = "LifetimeConstraintControl";
      this.Size = new System.Drawing.Size(158, 20);
      this.mTableLayoutPanel.ResumeLayout(false);
      this.mTableLayoutPanel.PerformLayout();
      this.ResumeLayout(false);
      this.PerformLayout();

    }

    #endregion

    private System.Windows.Forms.TableLayoutPanel mTableLayoutPanel;
    private System.Windows.Forms.CheckBox mLifetimeCheckBox;
    private System.Windows.Forms.TextBox mLifetimeTextBox;
    private System.Windows.Forms.Label mTimeUnitsLabel;
  }
}
