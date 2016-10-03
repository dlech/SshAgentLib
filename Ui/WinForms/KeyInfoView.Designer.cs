namespace dlech.SshAgentLib.WinForms
{
  partial class KeyInfoView
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
      this.components = new System.ComponentModel.Container();
      this.messageLabel = new System.Windows.Forms.Label();
      this.dataGridView = new System.Windows.Forms.DataGridView();
      this.keyWrapperBindingSource = new System.Windows.Forms.BindingSource(this.components);
      this.mainTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
      this.dataGridViewPanel = new System.Windows.Forms.Panel();
      this.buttonTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
      this.lockButton = new System.Windows.Forms.Button();
      this.unlockButton = new System.Windows.Forms.Button();
      this.addKeyButton = new wyDay.Controls.SplitButton();
      this.removeKeyButton = new System.Windows.Forms.Button();
      this.removeAllButton = new System.Windows.Forms.Button();
      this.refreshButton = new System.Windows.Forms.Button();
      this.confirmDataGridViewCheckBoxColumn = new System.Windows.Forms.DataGridViewCheckBoxColumn();
      this.lifetimeDataGridViewCheckBoxColumn = new System.Windows.Forms.DataGridViewCheckBoxColumn();
      this.commentDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
      this.sourceDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
      this.typeDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
      this.sizeDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
      this.fingerprintDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
      ((System.ComponentModel.ISupportInitialize)(this.dataGridView)).BeginInit();
      ((System.ComponentModel.ISupportInitialize)(this.keyWrapperBindingSource)).BeginInit();
      this.mainTableLayoutPanel.SuspendLayout();
      this.dataGridViewPanel.SuspendLayout();
      this.buttonTableLayoutPanel.SuspendLayout();
      this.SuspendLayout();
      // 
      // messageLabel
      // 
      this.messageLabel.AllowDrop = true;
      this.messageLabel.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
      this.messageLabel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.messageLabel.Location = new System.Drawing.Point(0, 0);
      this.messageLabel.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
      this.messageLabel.Name = "messageLabel";
      this.messageLabel.Size = new System.Drawing.Size(1094, 391);
      this.messageLabel.TabIndex = 0;
      this.messageLabel.Text = "Message";
      this.messageLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
      this.messageLabel.DragDrop += new System.Windows.Forms.DragEventHandler(this.dataGridView_DragDrop);
      this.messageLabel.DragEnter += new System.Windows.Forms.DragEventHandler(this.dataGridView_DragEnter);
      // 
      // dataGridView
      // 
      this.dataGridView.AllowDrop = true;
      this.dataGridView.AllowUserToAddRows = false;
      this.dataGridView.AllowUserToDeleteRows = false;
      this.dataGridView.AllowUserToResizeRows = false;
      this.dataGridView.AutoGenerateColumns = false;
      this.dataGridView.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
      this.dataGridView.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.confirmDataGridViewCheckBoxColumn,
            this.lifetimeDataGridViewCheckBoxColumn,
            this.commentDataGridViewTextBoxColumn,
            this.sourceDataGridViewTextBoxColumn,
            this.typeDataGridViewTextBoxColumn,
            this.sizeDataGridViewTextBoxColumn,
            this.fingerprintDataGridViewTextBoxColumn});
      this.dataGridView.DataSource = this.keyWrapperBindingSource;
      this.dataGridView.Dock = System.Windows.Forms.DockStyle.Fill;
      this.dataGridView.Location = new System.Drawing.Point(0, 0);
      this.dataGridView.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.dataGridView.Name = "dataGridView";
      this.dataGridView.ReadOnly = true;
      this.dataGridView.RowHeadersVisible = false;
      this.dataGridView.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
      this.dataGridView.Size = new System.Drawing.Size(1094, 391);
      this.dataGridView.TabIndex = 0;
      this.dataGridView.CellPainting += new System.Windows.Forms.DataGridViewCellPaintingEventHandler(this.dataGridView_CellPainting);
      this.dataGridView.SelectionChanged += new System.EventHandler(this.dataGridView_SelectionChanged);
      this.dataGridView.DragDrop += new System.Windows.Forms.DragEventHandler(this.dataGridView_DragDrop);
      this.dataGridView.DragEnter += new System.Windows.Forms.DragEventHandler(this.dataGridView_DragEnter);
      // 
      // keyWrapperBindingSource
      // 
      this.keyWrapperBindingSource.DataSource = typeof(dlech.SshAgentLib.KeyWrapper);
      // 
      // mainTableLayoutPanel
      // 
      this.mainTableLayoutPanel.ColumnCount = 1;
      this.mainTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
      this.mainTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
      this.mainTableLayoutPanel.Controls.Add(this.dataGridViewPanel, 0, 0);
      this.mainTableLayoutPanel.Controls.Add(this.buttonTableLayoutPanel, 0, 1);
      this.mainTableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.mainTableLayoutPanel.Location = new System.Drawing.Point(0, 0);
      this.mainTableLayoutPanel.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.mainTableLayoutPanel.Name = "mainTableLayoutPanel";
      this.mainTableLayoutPanel.RowCount = 2;
      this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
      this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle());
      this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 42F));
      this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 38F));
      this.mainTableLayoutPanel.Size = new System.Drawing.Size(1106, 494);
      this.mainTableLayoutPanel.TabIndex = 0;
      // 
      // dataGridViewPanel
      // 
      this.dataGridViewPanel.Controls.Add(this.dataGridView);
      this.dataGridViewPanel.Controls.Add(this.messageLabel);
      this.dataGridViewPanel.Dock = System.Windows.Forms.DockStyle.Fill;
      this.dataGridViewPanel.Location = new System.Drawing.Point(6, 6);
      this.dataGridViewPanel.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.dataGridViewPanel.Name = "dataGridViewPanel";
      this.dataGridViewPanel.Size = new System.Drawing.Size(1094, 391);
      this.dataGridViewPanel.TabIndex = 9;
      // 
      // buttonTableLayoutPanel
      // 
      this.buttonTableLayoutPanel.Anchor = System.Windows.Forms.AnchorStyles.Bottom;
      this.buttonTableLayoutPanel.AutoSize = true;
      this.buttonTableLayoutPanel.ColumnCount = 6;
      this.buttonTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 16.66667F));
      this.buttonTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 16.66667F));
      this.buttonTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 16.66667F));
      this.buttonTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 16.66667F));
      this.buttonTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 16.66667F));
      this.buttonTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 16.66667F));
      this.buttonTableLayoutPanel.Controls.Add(this.lockButton, 0, 0);
      this.buttonTableLayoutPanel.Controls.Add(this.unlockButton, 1, 0);
      this.buttonTableLayoutPanel.Controls.Add(this.addKeyButton, 2, 0);
      this.buttonTableLayoutPanel.Controls.Add(this.removeKeyButton, 3, 0);
      this.buttonTableLayoutPanel.Controls.Add(this.removeAllButton, 4, 0);
      this.buttonTableLayoutPanel.Controls.Add(this.refreshButton, 5, 0);
      this.buttonTableLayoutPanel.Location = new System.Drawing.Point(0, 415);
      this.buttonTableLayoutPanel.Margin = new System.Windows.Forms.Padding(0, 12, 0, 0);
      this.buttonTableLayoutPanel.Name = "buttonTableLayoutPanel";
      this.buttonTableLayoutPanel.RowCount = 1;
      this.buttonTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
      this.buttonTableLayoutPanel.Size = new System.Drawing.Size(1106, 79);
      this.buttonTableLayoutPanel.TabIndex = 0;
      // 
      // lockButton
      // 
      this.lockButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
      this.lockButton.AutoSize = true;
      this.lockButton.Location = new System.Drawing.Point(6, 6);
      this.lockButton.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.lockButton.Name = "lockButton";
      this.lockButton.Size = new System.Drawing.Size(172, 67);
      this.lockButton.TabIndex = 0;
      this.lockButton.Text = "&Lock";
      this.lockButton.UseVisualStyleBackColor = true;
      this.lockButton.Click += new System.EventHandler(this.lockButton_Click);
      // 
      // unlockButton
      // 
      this.unlockButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
      this.unlockButton.AutoSize = true;
      this.unlockButton.Location = new System.Drawing.Point(190, 6);
      this.unlockButton.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.unlockButton.Name = "unlockButton";
      this.unlockButton.Size = new System.Drawing.Size(172, 67);
      this.unlockButton.TabIndex = 1;
      this.unlockButton.Text = "&Unlock";
      this.unlockButton.UseVisualStyleBackColor = true;
      this.unlockButton.Click += new System.EventHandler(this.unlockButton_Click);
      // 
      // addKeyButton
      // 
      this.addKeyButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
      this.addKeyButton.AutoSize = true;
      this.addKeyButton.Location = new System.Drawing.Point(374, 6);
      this.addKeyButton.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.addKeyButton.Name = "addKeyButton";
      this.addKeyButton.Size = new System.Drawing.Size(172, 67);
      this.addKeyButton.TabIndex = 2;
      this.addKeyButton.Text = "&Add...";
      this.addKeyButton.UseVisualStyleBackColor = true;
      this.addKeyButton.Click += new System.EventHandler(this.addKeyButton_Click);
      // 
      // removeKeyButton
      // 
      this.removeKeyButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
      this.removeKeyButton.AutoSize = true;
      this.removeKeyButton.Location = new System.Drawing.Point(558, 6);
      this.removeKeyButton.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.removeKeyButton.Name = "removeKeyButton";
      this.removeKeyButton.Size = new System.Drawing.Size(172, 67);
      this.removeKeyButton.TabIndex = 3;
      this.removeKeyButton.Text = "&Remove";
      this.removeKeyButton.UseVisualStyleBackColor = true;
      this.removeKeyButton.Click += new System.EventHandler(this.removeButton_Click);
      // 
      // removeAllButton
      // 
      this.removeAllButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
      this.removeAllButton.AutoSize = true;
      this.removeAllButton.Location = new System.Drawing.Point(742, 6);
      this.removeAllButton.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.removeAllButton.Name = "removeAllButton";
      this.removeAllButton.Size = new System.Drawing.Size(172, 67);
      this.removeAllButton.TabIndex = 4;
      this.removeAllButton.Text = "R&emove All";
      this.removeAllButton.UseVisualStyleBackColor = true;
      this.removeAllButton.Click += new System.EventHandler(this.removeAllButton_Click);
      // 
      // refreshButton
      // 
      this.refreshButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
      this.refreshButton.AutoSize = true;
      this.refreshButton.Location = new System.Drawing.Point(926, 6);
      this.refreshButton.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.refreshButton.Name = "refreshButton";
      this.refreshButton.Size = new System.Drawing.Size(174, 67);
      this.refreshButton.TabIndex = 5;
      this.refreshButton.Text = "Re&fresh";
      this.refreshButton.UseVisualStyleBackColor = true;
      this.refreshButton.Click += new System.EventHandler(this.refreshButton_Click);
      // 
      // confirmDataGridViewCheckBoxColumn
      // 
      this.confirmDataGridViewCheckBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.confirmDataGridViewCheckBoxColumn.DataPropertyName = "Confirm";
      this.confirmDataGridViewCheckBoxColumn.HeaderText = "C";
      this.confirmDataGridViewCheckBoxColumn.Name = "confirmDataGridViewCheckBoxColumn";
      this.confirmDataGridViewCheckBoxColumn.ReadOnly = true;
      this.confirmDataGridViewCheckBoxColumn.ToolTipText = "Confirm Constraint";
      this.confirmDataGridViewCheckBoxColumn.Width = 33;
      // 
      // lifetimeDataGridViewCheckBoxColumn
      // 
      this.lifetimeDataGridViewCheckBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.lifetimeDataGridViewCheckBoxColumn.DataPropertyName = "Lifetime";
      this.lifetimeDataGridViewCheckBoxColumn.HeaderText = "L";
      this.lifetimeDataGridViewCheckBoxColumn.Name = "lifetimeDataGridViewCheckBoxColumn";
      this.lifetimeDataGridViewCheckBoxColumn.ReadOnly = true;
      this.lifetimeDataGridViewCheckBoxColumn.ToolTipText = "Lifetime Constraint";
      this.lifetimeDataGridViewCheckBoxColumn.Width = 30;
      // 
      // commentDataGridViewTextBoxColumn
      // 
      this.commentDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.commentDataGridViewTextBoxColumn.DataPropertyName = "Comment";
      this.commentDataGridViewTextBoxColumn.HeaderText = "Comment";
      this.commentDataGridViewTextBoxColumn.Name = "commentDataGridViewTextBoxColumn";
      this.commentDataGridViewTextBoxColumn.ReadOnly = true;
      this.commentDataGridViewTextBoxColumn.Width = 148;
      // 
      // sourceDataGridViewTextBoxColumn
      // 
      this.sourceDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.sourceDataGridViewTextBoxColumn.DataPropertyName = "Source";
      this.sourceDataGridViewTextBoxColumn.HeaderText = "Source";
      this.sourceDataGridViewTextBoxColumn.Name = "sourceDataGridViewTextBoxColumn";
      this.sourceDataGridViewTextBoxColumn.ReadOnly = true;
      this.sourceDataGridViewTextBoxColumn.Width = 125;
      // 
      // typeDataGridViewTextBoxColumn
      // 
      this.typeDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.typeDataGridViewTextBoxColumn.DataPropertyName = "Type";
      this.typeDataGridViewTextBoxColumn.HeaderText = "Type";
      this.typeDataGridViewTextBoxColumn.Name = "typeDataGridViewTextBoxColumn";
      this.typeDataGridViewTextBoxColumn.ReadOnly = true;
      this.typeDataGridViewTextBoxColumn.Width = 105;
      // 
      // sizeDataGridViewTextBoxColumn
      // 
      this.sizeDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.sizeDataGridViewTextBoxColumn.DataPropertyName = "Size";
      this.sizeDataGridViewTextBoxColumn.HeaderText = "Size";
      this.sizeDataGridViewTextBoxColumn.Name = "sizeDataGridViewTextBoxColumn";
      this.sizeDataGridViewTextBoxColumn.ReadOnly = true;
      this.sizeDataGridViewTextBoxColumn.Width = 99;
      // 
      // fingerprintDataGridViewTextBoxColumn
      // 
      this.fingerprintDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
      this.fingerprintDataGridViewTextBoxColumn.DataPropertyName = "Fingerprint";
      this.fingerprintDataGridViewTextBoxColumn.HeaderText = "Fingerprint";
      this.fingerprintDataGridViewTextBoxColumn.Name = "fingerprintDataGridViewTextBoxColumn";
      this.fingerprintDataGridViewTextBoxColumn.ReadOnly = true;
      this.fingerprintDataGridViewTextBoxColumn.Width = 160;
      // 
      // KeyInfoView
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.Controls.Add(this.mainTableLayoutPanel);
      this.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
      this.Name = "KeyInfoView";
      this.Size = new System.Drawing.Size(1106, 494);
      ((System.ComponentModel.ISupportInitialize)(this.dataGridView)).EndInit();
      ((System.ComponentModel.ISupportInitialize)(this.keyWrapperBindingSource)).EndInit();
      this.mainTableLayoutPanel.ResumeLayout(false);
      this.mainTableLayoutPanel.PerformLayout();
      this.dataGridViewPanel.ResumeLayout(false);
      this.buttonTableLayoutPanel.ResumeLayout(false);
      this.buttonTableLayoutPanel.PerformLayout();
      this.ResumeLayout(false);

    }

    #endregion

    private System.Windows.Forms.Label messageLabel;
    private System.Windows.Forms.BindingSource keyWrapperBindingSource;
    public System.Windows.Forms.DataGridView dataGridView;
    private System.Windows.Forms.TableLayoutPanel mainTableLayoutPanel;
    private System.Windows.Forms.TableLayoutPanel buttonTableLayoutPanel;
    private System.Windows.Forms.Button lockButton;
    private System.Windows.Forms.Button unlockButton;
    private System.Windows.Forms.Button removeKeyButton;
    private System.Windows.Forms.Button removeAllButton;
    private System.Windows.Forms.Button refreshButton;
    private System.Windows.Forms.Panel dataGridViewPanel;
    private wyDay.Controls.SplitButton addKeyButton;
    private System.Windows.Forms.DataGridViewCheckBoxColumn confirmDataGridViewCheckBoxColumn;
    private System.Windows.Forms.DataGridViewCheckBoxColumn lifetimeDataGridViewCheckBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn commentDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn sourceDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn typeDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn sizeDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn fingerprintDataGridViewTextBoxColumn;
  }
}
