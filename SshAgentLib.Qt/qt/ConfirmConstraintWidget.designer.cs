/********************************************************************************
** Form generated from reading ui file 'ConfirmConstraintWidget.ui'
**
** Created: Sat Feb 16 20:46:46 2013
**      by: Qt User Interface Compiler for C# version 4.8.3
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/


using QtCore;
using QtGui;

namespace dlech.SshAgentLib.QtAgent {

public partial class ConfirmConstraintWidget
{
    private QHBoxLayout horizontalLayout;
    private QCheckBox mCheckBox;
    private QSpacerItem spacerItem;

    public void SetupUi(QWidget ConfirmConstraintWidget)
    {
        if (ConfirmConstraintWidget.ObjectName == "")
            ConfirmConstraintWidget.ObjectName = "ConfirmConstraintWidget";
        horizontalLayout = new QHBoxLayout(ConfirmConstraintWidget);
    horizontalLayout.Spacing = 6;
    horizontalLayout.Margin = 0;
        horizontalLayout.ObjectName = "horizontalLayout";
        horizontalLayout.sizeConstraint = QLayout.SizeConstraint.SetNoConstraint;
        mCheckBox = new QCheckBox(ConfirmConstraintWidget);
        mCheckBox.ObjectName = "mCheckBox";

        horizontalLayout.AddWidget(mCheckBox);

        spacerItem = new QSpacerItem(111, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum);

        horizontalLayout.AddItem(spacerItem);


        RetranslateUi(ConfirmConstraintWidget);

        QMetaObject.ConnectSlotsByName(ConfirmConstraintWidget);
    } // SetupUi

    public void RetranslateUi(QWidget ConfirmConstraintWidget)
    {
        ConfirmConstraintWidget.WindowTitle = QApplication.Translate("ConfirmConstraintWidget", "Form", null, QApplication.Encoding.UnicodeUTF8);
        mCheckBox.ToolTip = QApplication.Translate("ConfirmConstraintWidget", "User confirmation will be required each time this key is used to authenticate", null, QApplication.Encoding.UnicodeUTF8);
        mCheckBox.Text = QApplication.Translate("ConfirmConstraintWidget", "Require confirmation", null, QApplication.Encoding.UnicodeUTF8);
    } // RetranslateUi

}

} // namespace dlech.SshAgentLib.QtAgent

