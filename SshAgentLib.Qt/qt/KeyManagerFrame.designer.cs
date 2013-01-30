/********************************************************************************
** Form generated from reading ui file 'KeyManagerFrame.ui'
**
** Created: Tue Jan 29 23:43:09 2013
**      by: Qt User Interface Compiler for C# version 4.8.3
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/


using QtCore;
using QtGui;

namespace dlech.SshAgentLib.QtAgent {

public partial class KeyManagerFrame
{
    public QVBoxLayout verticalLayout;
    public QStackedWidget mStackedWidget;
    public QWidget mMessagePage;
    public QHBoxLayout horizontalLayout_3;
    public QLabel mMessageLabel;
    public QWidget mTablePage;
    public QHBoxLayout horizontalLayout_2;
    public QTableView mTableView;
    public QHBoxLayout mButtonLayout;
    public QPushButton mLockButton;
    public QPushButton mUnlockButton;
    public QPushButton mAddButton;
    public QPushButton mRemoveButton;
    public QPushButton mRemoveAllButton;
    public QPushButton mRefreshButton;

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
    horizontalLayout_3.Margin = 0;
        horizontalLayout_3.ObjectName = "horizontalLayout_3";
        mMessageLabel = new QLabel(mMessagePage);
        mMessageLabel.ObjectName = "mMessageLabel";
        QFont font = new QFont();
        font.PointSize = 12;
        mMessageLabel.Font = font;
        mMessageLabel.Alignment = Qt.AlignmentFlag.AlignCenter;

        horizontalLayout_3.AddWidget(mMessageLabel);

        mStackedWidget.AddWidget(mMessagePage);
        mTablePage = new QWidget();
        mTablePage.ObjectName = "mTablePage";
        horizontalLayout_2 = new QHBoxLayout(mTablePage);
    horizontalLayout_2.Margin = 0;
        horizontalLayout_2.ObjectName = "horizontalLayout_2";
        mTableView = new QTableView(mTablePage);
        mTableView.ObjectName = "mTableView";
        mTableView.selectionBehavior = QAbstractItemView.SelectionBehavior.SelectRows;
        mTableView.VerticalHeader.Visible = false;

        horizontalLayout_2.AddWidget(mTableView);

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
        mLockButton.Text = QApplication.Translate("KeyManagerFrame", "Lock", null, QApplication.Encoding.UnicodeUTF8);
        mUnlockButton.Text = QApplication.Translate("KeyManagerFrame", "Unlock", null, QApplication.Encoding.UnicodeUTF8);
        mAddButton.Text = QApplication.Translate("KeyManagerFrame", "Add...", null, QApplication.Encoding.UnicodeUTF8);
        mRemoveButton.Text = QApplication.Translate("KeyManagerFrame", "Remove", null, QApplication.Encoding.UnicodeUTF8);
        mRemoveAllButton.Text = QApplication.Translate("KeyManagerFrame", "Remove All", null, QApplication.Encoding.UnicodeUTF8);
        mRefreshButton.Text = QApplication.Translate("KeyManagerFrame", "Refresh", null, QApplication.Encoding.UnicodeUTF8);
    } // RetranslateUi

}

} // namespace dlech.SshAgentLib.QtAgent

