/********************************************************************************
** Form generated from reading ui file 'KeyManagerFrame.ui'
**
** Created: Wed Feb 20 23:29:13 2013
**      by: Qt User Interface Compiler for C# version 4.8.3
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/


using QtCore;
using QtGui;

namespace dlech.SshAgentLib.Ui.QtAgent {

public partial class KeyManagerFrame
{
    private QVBoxLayout verticalLayout;
    private QStackedWidget mStackedWidget;
    private QWidget mMessagePage;
    private QHBoxLayout horizontalLayout_3;
    private QLabel mMessageLabel;
    private QWidget mTablePage;
    private QHBoxLayout horizontalLayout_2;
    private QTableWidget mTableWidget;
    private QHBoxLayout mButtonLayout;
    private QPushButton mLockButton;
    private QPushButton mUnlockButton;
    private QPushButton mAddButton;
    private QPushButton mRemoveButton;
    private QPushButton mRemoveAllButton;
    private QPushButton mRefreshButton;

    public void SetupUi(QWidget KeyManagerFrame)
    {
        if (KeyManagerFrame.ObjectName == "")
            KeyManagerFrame.ObjectName = "KeyManagerFrame";
        QSize Size = new QSize(656, 334);
        Size = Size.ExpandedTo(KeyManagerFrame.MinimumSizeHint);
        KeyManagerFrame.Size = Size;
        verticalLayout = new QVBoxLayout(KeyManagerFrame);
            verticalLayout.ObjectName = "verticalLayout";
        mStackedWidget = new QStackedWidget(KeyManagerFrame);
        mStackedWidget.ObjectName = "mStackedWidget";
        mMessagePage = new QWidget();
        mMessagePage.ObjectName = "mMessagePage";
        horizontalLayout_3 = new QHBoxLayout(mMessagePage);
        horizontalLayout_3.SetContentsMargins(0, 0, 0, 0);
        horizontalLayout_3.ObjectName = "horizontalLayout_3";
        mMessageLabel = new QLabel(mMessagePage);
        mMessageLabel.ObjectName = "mMessageLabel";
        QFont font = new QFont();
        font.PointSize = 12;
        mMessageLabel.Font = font;
        mMessageLabel.AcceptDrops = true;
        mMessageLabel.Alignment = Qt.AlignmentFlag.AlignCenter;

        horizontalLayout_3.AddWidget(mMessageLabel);

        mStackedWidget.AddWidget(mMessagePage);
        mTablePage = new QWidget();
        mTablePage.ObjectName = "mTablePage";
        horizontalLayout_2 = new QHBoxLayout(mTablePage);
        horizontalLayout_2.SetContentsMargins(0, 0, 0, 0);
        horizontalLayout_2.ObjectName = "horizontalLayout_2";
        mTableWidget = new QTableWidget(mTablePage);
        mTableWidget.ObjectName = "mTableWidget";
        mTableWidget.AcceptDrops = true;
        mTableWidget.EditTriggers = QAbstractItemView.EditTrigger.NoEditTriggers;
        mTableWidget.dragDropMode = QAbstractItemView.DragDropMode.DropOnly;
        mTableWidget.selectionBehavior = QAbstractItemView.SelectionBehavior.SelectRows;
        mTableWidget.WordWrap = false;
        mTableWidget.RowCount = 0;
        mTableWidget.ColumnCount = 6;
        mTableWidget.VerticalHeader.Visible = false;

        horizontalLayout_2.AddWidget(mTableWidget);

        mStackedWidget.AddWidget(mTablePage);

        verticalLayout.AddWidget(mStackedWidget);

        mButtonLayout = new QHBoxLayout();
            mButtonLayout.ObjectName = "mButtonLayout";
        mLockButton = new QPushButton(KeyManagerFrame);
        mLockButton.ObjectName = "mLockButton";
        mLockButton.Checkable = false;

        mButtonLayout.AddWidget(mLockButton);

        mUnlockButton = new QPushButton(KeyManagerFrame);
        mUnlockButton.ObjectName = "mUnlockButton";

        mButtonLayout.AddWidget(mUnlockButton);

        mAddButton = new QPushButton(KeyManagerFrame);
        mAddButton.ObjectName = "mAddButton";

        mButtonLayout.AddWidget(mAddButton);

        mRemoveButton = new QPushButton(KeyManagerFrame);
        mRemoveButton.ObjectName = "mRemoveButton";

        mButtonLayout.AddWidget(mRemoveButton);

        mRemoveAllButton = new QPushButton(KeyManagerFrame);
        mRemoveAllButton.ObjectName = "mRemoveAllButton";

        mButtonLayout.AddWidget(mRemoveAllButton);

        mRefreshButton = new QPushButton(KeyManagerFrame);
        mRefreshButton.ObjectName = "mRefreshButton";

        mButtonLayout.AddWidget(mRefreshButton);


        verticalLayout.AddLayout(mButtonLayout);


        RetranslateUi(KeyManagerFrame);

        mStackedWidget.CurrentIndex = 1;


        QMetaObject.ConnectSlotsByName(KeyManagerFrame);
    } // SetupUi

    public void RetranslateUi(QWidget KeyManagerFrame)
    {
        KeyManagerFrame.WindowTitle = QApplication.Translate("KeyManagerFrame", "Dialog", null, QApplication.Encoding.UnicodeUTF8);
        mMessageLabel.Text = QApplication.Translate("KeyManagerFrame", "Message", null, QApplication.Encoding.UnicodeUTF8);
        if (mTableWidget.ColumnCount < 6)
                mTableWidget.ColumnCount = 6;

        QTableWidgetItem __colItem = new QTableWidgetItem();
        __colItem.Text = QApplication.Translate("KeyManagerFrame", "C", null, QApplication.Encoding.UnicodeUTF8);
        mTableWidget.SetHorizontalHeaderItem(0, __colItem);

        QTableWidgetItem __colItem1 = new QTableWidgetItem();
        __colItem1.Text = QApplication.Translate("KeyManagerFrame", "L", null, QApplication.Encoding.UnicodeUTF8);
        mTableWidget.SetHorizontalHeaderItem(1, __colItem1);

        QTableWidgetItem __colItem2 = new QTableWidgetItem();
        __colItem2.Text = QApplication.Translate("KeyManagerFrame", "Type", null, QApplication.Encoding.UnicodeUTF8);
        mTableWidget.SetHorizontalHeaderItem(2, __colItem2);

        QTableWidgetItem __colItem3 = new QTableWidgetItem();
        __colItem3.Text = QApplication.Translate("KeyManagerFrame", "Size", null, QApplication.Encoding.UnicodeUTF8);
        mTableWidget.SetHorizontalHeaderItem(3, __colItem3);

        QTableWidgetItem __colItem4 = new QTableWidgetItem();
        __colItem4.Text = QApplication.Translate("KeyManagerFrame", "Fingerprint", null, QApplication.Encoding.UnicodeUTF8);
        mTableWidget.SetHorizontalHeaderItem(4, __colItem4);

        QTableWidgetItem __colItem5 = new QTableWidgetItem();
        __colItem5.Text = QApplication.Translate("KeyManagerFrame", "Comment", null, QApplication.Encoding.UnicodeUTF8);
        mTableWidget.SetHorizontalHeaderItem(5, __colItem5);
        mLockButton.Text = QApplication.Translate("KeyManagerFrame", "Lock", null, QApplication.Encoding.UnicodeUTF8);
        mUnlockButton.Text = QApplication.Translate("KeyManagerFrame", "Unlock", null, QApplication.Encoding.UnicodeUTF8);
        mAddButton.Text = QApplication.Translate("KeyManagerFrame", "Add...", null, QApplication.Encoding.UnicodeUTF8);
        mRemoveButton.Text = QApplication.Translate("KeyManagerFrame", "Remove", null, QApplication.Encoding.UnicodeUTF8);
        mRemoveAllButton.Text = QApplication.Translate("KeyManagerFrame", "Remove All", null, QApplication.Encoding.UnicodeUTF8);
        mRefreshButton.Text = QApplication.Translate("KeyManagerFrame", "Refresh", null, QApplication.Encoding.UnicodeUTF8);
    } // RetranslateUi

}

} // namespace dlech.SshAgentLib.Ui.QtAgent

