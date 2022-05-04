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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(KeyInfoView));
            this.messageLabel = new System.Windows.Forms.Label();
            this.dataGridView = new System.Windows.Forms.DataGridView();
            this.confirmDataGridViewCheckBoxColumn = new System.Windows.Forms.DataGridViewCheckBoxColumn();
            this.lifetimeDataGridViewCheckBoxColumn = new System.Windows.Forms.DataGridViewCheckBoxColumn();
            this.commentDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.sourceDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.typeDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.sizeDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.fingerprintDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.keyWrapperBindingSource = new System.Windows.Forms.BindingSource(this.components);
            this.mainTableLayoutPanel = new System.Windows.Forms.TableLayoutPanel();
            this.dataGridViewPanel = new System.Windows.Forms.Panel();
            this.toolStrip = new System.Windows.Forms.ToolStrip();
            this.addKeyButton = new System.Windows.Forms.ToolStripDropDownButton();
            this.removeKeyButton = new System.Windows.Forms.ToolStripButton();
            this.removeAllKeysButton = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.refreshAgentButton = new System.Windows.Forms.ToolStripButton();
            this.lockAgentButton = new System.Windows.Forms.ToolStripButton();
            this.unlockAgentButton = new System.Windows.Forms.ToolStripButton();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.removeKeyToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItemCopyAuthorizedKeys = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            this.copyPublicKeyButton = new System.Windows.Forms.ToolStripButton();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.keyWrapperBindingSource)).BeginInit();
            this.mainTableLayoutPanel.SuspendLayout();
            this.dataGridViewPanel.SuspendLayout();
            this.toolStrip.SuspendLayout();
            this.contextMenuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // messageLabel
            // 
            this.messageLabel.AllowDrop = true;
            this.messageLabel.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.messageLabel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.messageLabel.Location = new System.Drawing.Point(0, 0);
            this.messageLabel.Name = "messageLabel";
            this.messageLabel.Size = new System.Drawing.Size(547, 231);
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
            this.dataGridView.Name = "dataGridView";
            this.dataGridView.ReadOnly = true;
            this.dataGridView.RowHeadersVisible = false;
            this.dataGridView.RowHeadersWidth = 82;
            this.dataGridView.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dataGridView.Size = new System.Drawing.Size(547, 231);
            this.dataGridView.TabIndex = 0;
            this.dataGridView.CellContextMenuStripNeeded += new System.Windows.Forms.DataGridViewCellContextMenuStripNeededEventHandler(this.dataGridView_CellContextMenuStripNeeded);
            this.dataGridView.CellPainting += new System.Windows.Forms.DataGridViewCellPaintingEventHandler(this.dataGridView_CellPainting);
            this.dataGridView.SelectionChanged += new System.EventHandler(this.dataGridView_SelectionChanged);
            this.dataGridView.DragDrop += new System.Windows.Forms.DragEventHandler(this.dataGridView_DragDrop);
            this.dataGridView.DragEnter += new System.Windows.Forms.DragEventHandler(this.dataGridView_DragEnter);
            // 
            // confirmDataGridViewCheckBoxColumn
            // 
            this.confirmDataGridViewCheckBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.confirmDataGridViewCheckBoxColumn.DataPropertyName = "Confirm";
            this.confirmDataGridViewCheckBoxColumn.HeaderText = "C";
            this.confirmDataGridViewCheckBoxColumn.MinimumWidth = 10;
            this.confirmDataGridViewCheckBoxColumn.Name = "confirmDataGridViewCheckBoxColumn";
            this.confirmDataGridViewCheckBoxColumn.ReadOnly = true;
            this.confirmDataGridViewCheckBoxColumn.ToolTipText = "Confirm Constraint";
            this.confirmDataGridViewCheckBoxColumn.Width = 20;
            // 
            // lifetimeDataGridViewCheckBoxColumn
            // 
            this.lifetimeDataGridViewCheckBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.lifetimeDataGridViewCheckBoxColumn.DataPropertyName = "Lifetime";
            this.lifetimeDataGridViewCheckBoxColumn.HeaderText = "L";
            this.lifetimeDataGridViewCheckBoxColumn.MinimumWidth = 10;
            this.lifetimeDataGridViewCheckBoxColumn.Name = "lifetimeDataGridViewCheckBoxColumn";
            this.lifetimeDataGridViewCheckBoxColumn.ReadOnly = true;
            this.lifetimeDataGridViewCheckBoxColumn.ToolTipText = "Lifetime Constraint";
            this.lifetimeDataGridViewCheckBoxColumn.Width = 19;
            // 
            // commentDataGridViewTextBoxColumn
            // 
            this.commentDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.commentDataGridViewTextBoxColumn.DataPropertyName = "Comment";
            this.commentDataGridViewTextBoxColumn.HeaderText = "Comment";
            this.commentDataGridViewTextBoxColumn.MinimumWidth = 10;
            this.commentDataGridViewTextBoxColumn.Name = "commentDataGridViewTextBoxColumn";
            this.commentDataGridViewTextBoxColumn.ReadOnly = true;
            this.commentDataGridViewTextBoxColumn.Width = 76;
            // 
            // sourceDataGridViewTextBoxColumn
            // 
            this.sourceDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.sourceDataGridViewTextBoxColumn.DataPropertyName = "Source";
            this.sourceDataGridViewTextBoxColumn.HeaderText = "Source";
            this.sourceDataGridViewTextBoxColumn.MinimumWidth = 10;
            this.sourceDataGridViewTextBoxColumn.Name = "sourceDataGridViewTextBoxColumn";
            this.sourceDataGridViewTextBoxColumn.ReadOnly = true;
            this.sourceDataGridViewTextBoxColumn.Width = 66;
            // 
            // typeDataGridViewTextBoxColumn
            // 
            this.typeDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.typeDataGridViewTextBoxColumn.DataPropertyName = "Type";
            this.typeDataGridViewTextBoxColumn.HeaderText = "Type";
            this.typeDataGridViewTextBoxColumn.MinimumWidth = 10;
            this.typeDataGridViewTextBoxColumn.Name = "typeDataGridViewTextBoxColumn";
            this.typeDataGridViewTextBoxColumn.ReadOnly = true;
            this.typeDataGridViewTextBoxColumn.Width = 56;
            // 
            // sizeDataGridViewTextBoxColumn
            // 
            this.sizeDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.sizeDataGridViewTextBoxColumn.DataPropertyName = "Size";
            this.sizeDataGridViewTextBoxColumn.HeaderText = "Size";
            this.sizeDataGridViewTextBoxColumn.MinimumWidth = 10;
            this.sizeDataGridViewTextBoxColumn.Name = "sizeDataGridViewTextBoxColumn";
            this.sizeDataGridViewTextBoxColumn.ReadOnly = true;
            this.sizeDataGridViewTextBoxColumn.Width = 52;
            // 
            // fingerprintDataGridViewTextBoxColumn
            // 
            this.fingerprintDataGridViewTextBoxColumn.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.AllCells;
            this.fingerprintDataGridViewTextBoxColumn.DataPropertyName = "Fingerprint";
            this.fingerprintDataGridViewTextBoxColumn.HeaderText = "Fingerprint";
            this.fingerprintDataGridViewTextBoxColumn.MinimumWidth = 10;
            this.fingerprintDataGridViewTextBoxColumn.Name = "fingerprintDataGridViewTextBoxColumn";
            this.fingerprintDataGridViewTextBoxColumn.ReadOnly = true;
            this.fingerprintDataGridViewTextBoxColumn.Width = 81;
            // 
            // keyWrapperBindingSource
            // 
            this.keyWrapperBindingSource.DataSource = typeof(dlech.SshAgentLib.KeyWrapper);
            // 
            // mainTableLayoutPanel
            // 
            this.mainTableLayoutPanel.ColumnCount = 1;
            this.mainTableLayoutPanel.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.mainTableLayoutPanel.Controls.Add(this.dataGridViewPanel, 0, 1);
            this.mainTableLayoutPanel.Controls.Add(this.toolStrip, 0, 0);
            this.mainTableLayoutPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.mainTableLayoutPanel.Location = new System.Drawing.Point(0, 0);
            this.mainTableLayoutPanel.Name = "mainTableLayoutPanel";
            this.mainTableLayoutPanel.RowCount = 2;
            this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 20F));
            this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.mainTableLayoutPanel.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 10F));
            this.mainTableLayoutPanel.Size = new System.Drawing.Size(553, 257);
            this.mainTableLayoutPanel.TabIndex = 0;
            // 
            // dataGridViewPanel
            // 
            this.dataGridViewPanel.Controls.Add(this.dataGridView);
            this.dataGridViewPanel.Controls.Add(this.messageLabel);
            this.dataGridViewPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dataGridViewPanel.Location = new System.Drawing.Point(3, 23);
            this.dataGridViewPanel.Name = "dataGridViewPanel";
            this.dataGridViewPanel.Size = new System.Drawing.Size(547, 231);
            this.dataGridViewPanel.TabIndex = 9;
            // 
            // toolStrip
            // 
            this.toolStrip.Dock = System.Windows.Forms.DockStyle.Fill;
            this.toolStrip.GripStyle = System.Windows.Forms.ToolStripGripStyle.Hidden;
            this.toolStrip.ImageScalingSize = new System.Drawing.Size(32, 32);
            this.toolStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.addKeyButton,
            this.removeKeyButton,
            this.removeAllKeysButton,
            this.toolStripSeparator1,
            this.refreshAgentButton,
            this.lockAgentButton,
            this.unlockAgentButton,
            this.toolStripSeparator2,
            this.copyPublicKeyButton});
            this.toolStrip.Location = new System.Drawing.Point(0, 0);
            this.toolStrip.Name = "toolStrip";
            this.toolStrip.Padding = new System.Windows.Forms.Padding(0, 0, 2, 0);
            this.toolStrip.RenderMode = System.Windows.Forms.ToolStripRenderMode.System;
            this.toolStrip.Size = new System.Drawing.Size(553, 20);
            this.toolStrip.TabIndex = 10;
            // 
            // addKeyButton
            // 
            this.addKeyButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.addKeyButton.Image = ((System.Drawing.Image)(resources.GetObject("addKeyButton.Image")));
            this.addKeyButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.addKeyButton.Name = "addKeyButton";
            this.addKeyButton.Size = new System.Drawing.Size(45, 17);
            this.addKeyButton.Text = "Add Key";
            this.addKeyButton.Click += new System.EventHandler(this.addKeyButton_Click);
            // 
            // removeKeyButton
            // 
            this.removeKeyButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.removeKeyButton.Image = ((System.Drawing.Image)(resources.GetObject("removeKeyButton.Image")));
            this.removeKeyButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.removeKeyButton.Name = "removeKeyButton";
            this.removeKeyButton.Size = new System.Drawing.Size(36, 17);
            this.removeKeyButton.Text = "Remove Key";
            this.removeKeyButton.Click += new System.EventHandler(this.removeKeyButton_Click);
            // 
            // removeAllKeysButton
            // 
            this.removeAllKeysButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.removeAllKeysButton.Image = ((System.Drawing.Image)(resources.GetObject("removeAllKeysButton.Image")));
            this.removeAllKeysButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.removeAllKeysButton.Name = "removeAllKeysButton";
            this.removeAllKeysButton.Size = new System.Drawing.Size(36, 17);
            this.removeAllKeysButton.Text = "Remove All Keys";
            this.removeAllKeysButton.Click += new System.EventHandler(this.removeAllKeysButton_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(6, 20);
            // 
            // refreshAgentButton
            // 
            this.refreshAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.refreshAgentButton.Image = ((System.Drawing.Image)(resources.GetObject("refreshAgentButton.Image")));
            this.refreshAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.refreshAgentButton.Name = "refreshAgentButton";
            this.refreshAgentButton.Size = new System.Drawing.Size(36, 17);
            this.refreshAgentButton.Text = "Refresh Keys From Agent";
            this.refreshAgentButton.Click += new System.EventHandler(this.refreshAgentButton_Click);
            // 
            // lockAgentButton
            // 
            this.lockAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.lockAgentButton.Image = ((System.Drawing.Image)(resources.GetObject("lockAgentButton.Image")));
            this.lockAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.lockAgentButton.Name = "lockAgentButton";
            this.lockAgentButton.Size = new System.Drawing.Size(36, 17);
            this.lockAgentButton.Text = "Lock Agent";
            this.lockAgentButton.Click += new System.EventHandler(this.lockAgentButton_Click);
            // 
            // unlockAgentButton
            // 
            this.unlockAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.unlockAgentButton.Image = ((System.Drawing.Image)(resources.GetObject("unlockAgentButton.Image")));
            this.unlockAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.unlockAgentButton.Name = "unlockAgentButton";
            this.unlockAgentButton.Size = new System.Drawing.Size(36, 17);
            this.unlockAgentButton.Text = "Unlock Agent";
            this.unlockAgentButton.Click += new System.EventHandler(this.unlockAgentButton_Click);
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.removeKeyToolStripMenuItem,
            this.toolStripMenuItemCopyAuthorizedKeys});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(220, 48);
            // 
            // removeKeyToolStripMenuItem
            // 
            this.removeKeyToolStripMenuItem.Name = "removeKeyToolStripMenuItem";
            this.removeKeyToolStripMenuItem.Size = new System.Drawing.Size(219, 22);
            this.removeKeyToolStripMenuItem.Text = "&Remove";
            this.removeKeyToolStripMenuItem.Click += new System.EventHandler(this.removeKeyToolStripMenuItem_Click);
            // 
            // toolStripMenuItemCopyAuthorizedKeys
            // 
            this.toolStripMenuItemCopyAuthorizedKeys.Name = "toolStripMenuItemCopyAuthorizedKeys";
            this.toolStripMenuItemCopyAuthorizedKeys.Size = new System.Drawing.Size(219, 22);
            this.toolStripMenuItemCopyAuthorizedKeys.Text = "Copy &authorized_keys Entry";
            this.toolStripMenuItemCopyAuthorizedKeys.Click += new System.EventHandler(this.toolStripMenuItemCopyAuthorizedKeys_Click);
            // 
            // toolStripSeparator2
            // 
            this.toolStripSeparator2.Name = "toolStripSeparator2";
            this.toolStripSeparator2.Size = new System.Drawing.Size(6, 20);
            // 
            // copyPublicKeyButton
            // 
            this.copyPublicKeyButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.copyPublicKeyButton.Image = ((System.Drawing.Image)(resources.GetObject("copyPublicKeyButton.Image")));
            this.copyPublicKeyButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.copyPublicKeyButton.Name = "copyPublicKeyButton";
            this.copyPublicKeyButton.Size = new System.Drawing.Size(36, 17);
            this.copyPublicKeyButton.Text = "Copy Public Key";
            this.copyPublicKeyButton.Click += new System.EventHandler(this.copyPublicKeyButton_Click);
            // 
            // KeyInfoView
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.mainTableLayoutPanel);
            this.Name = "KeyInfoView";
            this.Size = new System.Drawing.Size(553, 257);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.keyWrapperBindingSource)).EndInit();
            this.mainTableLayoutPanel.ResumeLayout(false);
            this.mainTableLayoutPanel.PerformLayout();
            this.dataGridViewPanel.ResumeLayout(false);
            this.toolStrip.ResumeLayout(false);
            this.toolStrip.PerformLayout();
            this.contextMenuStrip1.ResumeLayout(false);
            this.ResumeLayout(false);

    }

    #endregion

    private System.Windows.Forms.Label messageLabel;
    private System.Windows.Forms.BindingSource keyWrapperBindingSource;
    public System.Windows.Forms.DataGridView dataGridView;
    private System.Windows.Forms.TableLayoutPanel mainTableLayoutPanel;
    private System.Windows.Forms.Panel dataGridViewPanel;
    private System.Windows.Forms.DataGridViewCheckBoxColumn confirmDataGridViewCheckBoxColumn;
    private System.Windows.Forms.DataGridViewCheckBoxColumn lifetimeDataGridViewCheckBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn commentDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn sourceDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn typeDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn sizeDataGridViewTextBoxColumn;
    private System.Windows.Forms.DataGridViewTextBoxColumn fingerprintDataGridViewTextBoxColumn;
    private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
    private System.Windows.Forms.ToolStripMenuItem removeKeyToolStripMenuItem;
    private System.Windows.Forms.ToolStripMenuItem toolStripMenuItemCopyAuthorizedKeys;
        private System.Windows.Forms.ToolStrip toolStrip;
        private System.Windows.Forms.ToolStripButton lockAgentButton;
        private System.Windows.Forms.ToolStripButton unlockAgentButton;
        private System.Windows.Forms.ToolStripButton refreshAgentButton;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripDropDownButton addKeyButton;
        private System.Windows.Forms.ToolStripButton removeKeyButton;
        private System.Windows.Forms.ToolStripButton removeAllKeysButton;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.ToolStripButton copyPublicKeyButton;
    }
}
