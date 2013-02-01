/********************************************************************************
** Form generated from reading ui file 'PassphraseDialog.ui'
**
** Created: Thu Jan 31 23:52:16 2013
**      by: Qt User Interface Compiler for C# version 4.8.3
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/


using QtCore;
using QtGui;

namespace dlech.SshAgentLib.QtAgent {

public partial class PassphraseDialog
{
    private QVBoxLayout verticalLayout;
    private QLabel mMessageLabel;
    private QLineEdit mPassphraseLineEdit;
    private QDialogButtonBox mButtonBox;

    public void SetupUi(QDialog PassphraseDialog)
    {
        if (PassphraseDialog.ObjectName == "")
            PassphraseDialog.ObjectName = "PassphraseDialog";
        QSize Size = new QSize(493, 118);
        Size = Size.ExpandedTo(PassphraseDialog.MinimumSizeHint);
        PassphraseDialog.Size = Size;
        verticalLayout = new QVBoxLayout(PassphraseDialog);
        verticalLayout.ObjectName = "verticalLayout";
        mMessageLabel = new QLabel(PassphraseDialog);
        mMessageLabel.ObjectName = "mMessageLabel";

        verticalLayout.AddWidget(mMessageLabel, 0, Qt.AlignmentFlag.AlignHCenter);

        mPassphraseLineEdit = new QLineEdit(PassphraseDialog);
        mPassphraseLineEdit.ObjectName = "mPassphraseLineEdit";
        mPassphraseLineEdit.echoMode = QLineEdit.EchoMode.Password;

        verticalLayout.AddWidget(mPassphraseLineEdit);

        mButtonBox = new QDialogButtonBox(PassphraseDialog);
        mButtonBox.ObjectName = "mButtonBox";
        mButtonBox.Orientation = Qt.Orientation.Horizontal;
        mButtonBox.StandardButtons = QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok;

        verticalLayout.AddWidget(mButtonBox);


        RetranslateUi(PassphraseDialog);
        QObject.Connect(mButtonBox, Qt.SIGNAL("accepted()"), PassphraseDialog, Qt.SLOT("accept()"));
        QObject.Connect(mButtonBox, Qt.SIGNAL("rejected()"), PassphraseDialog, Qt.SLOT("reject()"));

        QMetaObject.ConnectSlotsByName(PassphraseDialog);
    } // SetupUi

    public void RetranslateUi(QDialog PassphraseDialog)
    {
        PassphraseDialog.WindowTitle = QApplication.Translate("PassphraseDialog", "Enter passphrase", null, QApplication.Encoding.UnicodeUTF8);
        mMessageLabel.Text = QApplication.Translate("PassphraseDialog", "Message", null, QApplication.Encoding.UnicodeUTF8);
    } // RetranslateUi

}

} // namespace dlech.SshAgentLib.QtAgent

