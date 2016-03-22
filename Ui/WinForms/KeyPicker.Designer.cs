namespace dlech.SshAgentLib.WinForms
{
  partial class KeyPicker
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
      this.selectButton = new System.Windows.Forms.Button();
      this.cancelButton = new System.Windows.Forms.Button();
      this.keyDataGridView = new System.Windows.Forms.DataGridView();
      ((System.ComponentModel.ISupportInitialize)(this.keyDataGridView)).BeginInit();
      this.SuspendLayout();
      // 
      // selectButton
      // 
      this.selectButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
      this.selectButton.DialogResult = System.Windows.Forms.DialogResult.OK;
      this.selectButton.Location = new System.Drawing.Point(498, 201);
      this.selectButton.Name = "selectButton";
      this.selectButton.Size = new System.Drawing.Size(75, 23);
      this.selectButton.TabIndex = 1;
      this.selectButton.Text = "&Select";
      this.selectButton.UseVisualStyleBackColor = true;
      // 
      // cancelButton
      // 
      this.cancelButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
      this.cancelButton.DialogResult = System.Windows.Forms.DialogResult.Cancel;
      this.cancelButton.Location = new System.Drawing.Point(579, 201);
      this.cancelButton.Name = "cancelButton";
      this.cancelButton.Size = new System.Drawing.Size(75, 23);
      this.cancelButton.TabIndex = 2;
      this.cancelButton.Text = "&Cancel";
      this.cancelButton.UseVisualStyleBackColor = true;
      // 
      // keyDataGridView
      // 
      this.keyDataGridView.AllowUserToAddRows = false;
      this.keyDataGridView.AllowUserToDeleteRows = false;
      this.keyDataGridView.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
      this.keyDataGridView.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
      this.keyDataGridView.Location = new System.Drawing.Point(12, 12);
      this.keyDataGridView.Name = "keyDataGridView";
      this.keyDataGridView.ReadOnly = true;
      this.keyDataGridView.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
      this.keyDataGridView.Size = new System.Drawing.Size(642, 183);
      this.keyDataGridView.TabIndex = 1;
      this.keyDataGridView.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.keyDataGridView_CellDoubleClick);
      this.keyDataGridView.KeyDown += new System.Windows.Forms.KeyEventHandler(this.keyDataGridView_KeyDown);
      // 
      // KeyPicker
      // 
      this.AcceptButton = this.selectButton;
      this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.CancelButton = this.cancelButton;
      this.ClientSize = new System.Drawing.Size(666, 236);
      this.Controls.Add(this.keyDataGridView);
      this.Controls.Add(this.cancelButton);
      this.Controls.Add(this.selectButton);
      this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
      this.MaximizeBox = false;
      this.MinimizeBox = false;
      this.Name = "KeyPicker";
      this.ShowIcon = false;
      this.ShowInTaskbar = false;
      this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
      this.Text = "Select a Key";
      ((System.ComponentModel.ISupportInitialize)(this.keyDataGridView)).EndInit();
      this.ResumeLayout(false);

    }

    #endregion

    private System.Windows.Forms.Button selectButton;
    private System.Windows.Forms.Button cancelButton;
    private System.Windows.Forms.DataGridView keyDataGridView;
  }
}