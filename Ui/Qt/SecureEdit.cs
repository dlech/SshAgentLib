using System;
using System.Security;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using QtCore;
using QtGui;

// Code from KeePass <http://keepass.info>

namespace dlech.SshAgentLib.Ui.QtAgent
{
  /// <summary>
  /// Secure edit control class. Supports storing passwords in an encrypted
  /// form in the process memory (Windows only).
  /// </summary>
  public sealed class SecureEdit : QObject
  {
    private static char cPasswordChar = '\u25CF';
    private QLineEdit mPasswordLineEdit = null;
    private EventHandler mTextChangedEventHandler = null;

    // SecureString objects are supported only on Windows 2000 SP3 and
    // higher. On all other systems (98 / ME) we use a standard string
    // object instead of the secure one. This of course decreases the
    // security of the control, but at least allows the application
    // to run on older systems, too.
    private SecureString mSecureString = null; // Created in constructor
    private PinnedArray<char> mAltSecureString = new PinnedArray<char>(0);
    private bool mBlockTextChanged = false;
    private bool mFirstGotFocus = true;
    private bool mSecureDesktop = false;

    public bool SecureDesktopMode { get; set; }

    public uint TextLength {
      get {
        if (mSecureString != null) {
          return (uint)mSecureString.Length;
        }
        return (uint)mAltSecureString.Data.Length;
      }
    }

    static SecureEdit()
    {
      // On Windows 98 / ME, an ANSI character must be used as
      // password char!
      if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
        cPasswordChar = '\u00D7';
    }

    /// <summary>
    /// Construct a new <c>SecureEdit</c> object. You must call the
    /// <c>Attach</c> member function to associate the secure edit control
    /// with a text box.
    /// </summary>
    public SecureEdit()
    {
      try {
        // There is a bug in mono where SecureString.RemoveAt(int) mangles the string.
        // so we won't use SecureString with mono until it is fixed.
        if (Type.GetType("Mono.Runtime") == null) {
          mSecureString = new SecureString();
        }
      } catch (NotSupportedException) {
        // Windows 98 / ME
      }
    }

    ~SecureEdit()
    {
      this.Detach();
    }

    /// <summary>
    /// Associate the current secure edit object with a text box.
    /// </summary>
    /// <param name="aLineEdit">Text box to link to.</param>
    /// <param name="aHidePassword">Initial protection flag.</param>
    public void Attach(QLineEdit aLineEdit, bool aHidePassword)
    {
      Debug.Assert(aLineEdit != null);
      if (aLineEdit == null) {
        throw new ArgumentNullException("aLineEdit");
      }

      this.Detach();

      mPasswordLineEdit = aLineEdit;

      // Initialize to zero-length string
      mPasswordLineEdit.Text = string.Empty;

      if (mSecureString != null) {
        mSecureString.Clear();
      } else {
        mAltSecureString.Clear();
        mAltSecureString.Data = new char[0];
      }

      EnableProtection(aHidePassword);

      if (mTextChangedEventHandler != null) {
        mTextChangedEventHandler(mPasswordLineEdit, EventArgs.Empty);
      }

      if (!mSecureDesktop) {
        mPasswordLineEdit.AcceptDrops = true;
      }

      // Register event handler
      mPasswordLineEdit.TextChanged += mPasswordLineEdit_TextChanged;
      mPasswordLineEdit.FocusInEvent += mPasswordLineEdit_FocusInEvent;
      if (!mSecureDesktop) {
        mPasswordLineEdit.DragEnterEvent += mPasswordLineEdit_DragEnterEvent;
        mPasswordLineEdit.DragMoveEvent += mPasswordLineEdit_DragMoveEvent;
        mPasswordLineEdit.DropEvent += mPasswordLineEdit_DropEvent;
      }
    }

    /// <summary>
    /// Remove the current association. You should call this before the
    /// text box is destroyed.
    /// </summary>
    public void Detach()
    {
      if (mPasswordLineEdit != null) {
        mPasswordLineEdit.TextChanged -= mPasswordLineEdit_TextChanged;
        mPasswordLineEdit.FocusInEvent -= mPasswordLineEdit_FocusInEvent;
        if (!mSecureDesktop) {
          mPasswordLineEdit.DragEnterEvent -= mPasswordLineEdit_DragEnterEvent;
          mPasswordLineEdit.DragMoveEvent -= mPasswordLineEdit_DragMoveEvent;
          mPasswordLineEdit.DropEvent -= mPasswordLineEdit_DropEvent;
        }
        mPasswordLineEdit = null;
      }
    }

    public void EnableProtection(bool aEnable)
    {
      if (mPasswordLineEdit == null) {
        Debug.Fail("mPasswordLineEdit is null");
        return;
      }

      var echoMode = aEnable ? QLineEdit.EchoMode.Password :
        QLineEdit.EchoMode.Normal;
      if (mPasswordLineEdit.echoMode == echoMode) {
        return;
      }
      mPasswordLineEdit.echoMode = echoMode;

      ShowCurrentPassword(mPasswordLineEdit.HasSelectedText ?
                            mPasswordLineEdit.SelectionStart :
                            mPasswordLineEdit.CursorPosition,
                          mPasswordLineEdit.HasSelectedText ?
                            mPasswordLineEdit.SelectedText.Length : 0
      );
    }

    [Q_SLOT]
    private void mPasswordLineEdit_TextChanged(string aText)
    {
      if (mPasswordLineEdit == null) {
        Debug.Fail("mPasswordLineEdit is null");
        return;
      }

      if (mBlockTextChanged) {
        return;
      }

      int nSelPos = mPasswordLineEdit.HasSelectedText ?
        mPasswordLineEdit.SelectionStart : mPasswordLineEdit.CursorPosition;
      int nSelLen = mPasswordLineEdit.HasSelectedText ?
        mPasswordLineEdit.SelectedText.Length : 0;

      if (mPasswordLineEdit.echoMode == QLineEdit.EchoMode.Normal) {
        RemoveInsert(0, 0, mPasswordLineEdit.Text);
        ShowCurrentPassword(nSelPos, nSelLen);
        return;
      }

      string strText = mPasswordLineEdit.Text;

      int leftIndex = -1, rightIndex = 0;
      StringBuilder newStringPart = new StringBuilder();

      for (int i = 0; i < strText.Length; ++i) {
        if (strText[i] != cPasswordChar) {
          if (leftIndex == -1) {
            leftIndex = i;
          }
          rightIndex = i;
          newStringPart.Append(strText[i]);
        }
      }

      if (leftIndex < 0) {
        RemoveInsert(nSelPos, strText.Length - nSelPos, string.Empty);
      } else {
        RemoveInsert(leftIndex, strText.Length - rightIndex - 1,
          newStringPart.ToString());
      }

      ShowCurrentPassword(nSelPos, nSelLen);
    }

    private void ShowCurrentPassword(int nSelStart, int nSelLength)
    {
      if (mPasswordLineEdit == null) {
        Debug.Assert(false);
        return;
      }

      if (mPasswordLineEdit.echoMode == QLineEdit.EchoMode.Normal) {
        mBlockTextChanged = true;
        mPasswordLineEdit.Text = GetAsString();
        mBlockTextChanged = false;

        if (mTextChangedEventHandler != null)
          mTextChangedEventHandler(mPasswordLineEdit, EventArgs.Empty);
        return;
      }

      mBlockTextChanged = true;
      if (mSecureString != null) {
        mPasswordLineEdit.Text = new string(cPasswordChar, mSecureString.Length);
      } else {
        mPasswordLineEdit.Text = new string(cPasswordChar,
                                            mAltSecureString.Data.Length);
      }
      mBlockTextChanged = false;

      mPasswordLineEdit.SetSelection(nSelStart, nSelLength);

      if (mTextChangedEventHandler != null) {
        mTextChangedEventHandler(mPasswordLineEdit, EventArgs.Empty);
      }
    }

    public byte[] ToUtf8()
    {
      Debug.Assert(sizeof(char) == 2);

      if (mSecureString != null) {
        char[] vChars = new char[mSecureString.Length];
        IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(mSecureString);
        for (int i = 0; i < mSecureString.Length; ++i) {
          vChars[i] = (char)Marshal.ReadInt16(p, i * 2);
        }
        Marshal.ZeroFreeGlobalAllocUnicode(p);

        byte[] pb = Encoding.UTF8.GetBytes(vChars);
        Array.Clear(vChars, 0, vChars.Length);

        return pb;
      } else
        return Encoding.UTF8.GetBytes(mAltSecureString.Data);
    }

    private string GetAsString()
    {
      if (mSecureString != null) {
        IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(mSecureString);
        string str = Marshal.PtrToStringUni(p);
        Marshal.ZeroFreeGlobalAllocUnicode(p);

        return str;
      } else {
        using (var bytes = new PinnedArray<byte>(
          Encoding.Unicode.GetBytes(mAltSecureString.Data)))
        {
          return Encoding.Unicode.GetString(bytes.Data);
        }
      }
    }

    private void RemoveInsert(int aLeftRemainingCount,
                              int aRigthRemainingCount,
                              string aStringToInsert)
    {
      Debug.Assert(aLeftRemainingCount >= 0);

      if (mSecureString != null) {
        while (mSecureString.Length > (aLeftRemainingCount +
                                       aRigthRemainingCount))
        {
          mSecureString.RemoveAt(aLeftRemainingCount);
        }
        for (int i = 0; i < aStringToInsert.Length; ++i) {
          mSecureString.InsertAt(aLeftRemainingCount + i, aStringToInsert[i]);
        }
      } else {
        using (var newString =
          new PinnedArray<char>(aLeftRemainingCount + aRigthRemainingCount + 
                                aStringToInsert.Length)) {
          Array.Copy(mAltSecureString.Data, newString.Data, aLeftRemainingCount);
          using (var insertString =
                 new PinnedArray<char>(Encoding.Unicode.GetChars(
                   Encoding.Unicode.GetBytes(aStringToInsert)))) {
            Array.Copy(insertString.Data, 0, newString.Data, aLeftRemainingCount,
                       insertString.Data.Length);
            Array.Copy(mAltSecureString.Data,
                       mAltSecureString.Data.Length - aRigthRemainingCount,
                       newString.Data, aLeftRemainingCount +
                       insertString.Data.Length,
                       aRigthRemainingCount);
          }
          mAltSecureString.Clear();
          mAltSecureString = newString.Clone() as PinnedArray<char>;
        }
      }
    }

    public bool ContentsEqualTo(SecureEdit aSecureEdit)
    {
      Debug.Assert(aSecureEdit != null);
      if (aSecureEdit == null) {
        return false;
      }

      using (var thisString = new PinnedArray<byte>(this.ToUtf8())) {
        using (var otherString = new PinnedArray<byte>(aSecureEdit.ToUtf8())) {

          if (thisString.Data.Length != otherString.Data.Length) {
            return false;
          } else {
            for (int i = 0; i < thisString.Data.Length; ++i) {
              if (thisString.Data[i] != otherString.Data [i]) {
                return false;
              }
            }
          }
          return true;
        }
      }
    }

    /// <summary>
    /// Sets the password.
    /// </summary>
    /// <param name='aNewPassword'>
    /// A new password (UTF8).
    /// </param>
    public void SetPassword(byte[] aNewPassword)
    {
      Debug.Assert(aNewPassword != null);
      if (aNewPassword == null) {
        throw new ArgumentNullException("aNewPassword");
      }

      if (mSecureString != null) {
        mSecureString.Clear();

        char[] vChars = Encoding.UTF8.GetChars(aNewPassword);

        for (int i = 0; i < vChars.Length; ++i) {
          mSecureString.AppendChar(vChars[i]);
          vChars[i] = char.MinValue;
        }
      } else
        mAltSecureString.Data = Encoding.UTF8.GetChars(aNewPassword);

      ShowCurrentPassword(0, 0);
    }

    [Q_SLOT]
    private void mPasswordLineEdit_FocusInEvent(object sender, EventArgs e)
    {
      if (mPasswordLineEdit == null) {
        Debug.Assert(false);
        return;
      }

      if (mFirstGotFocus && (mPasswordLineEdit != null)) {
        mPasswordLineEdit.SelectAll();
      }

      mFirstGotFocus = false;
    }

    [Q_SLOT]
    private void mPasswordLineEdit_DragEnterEvent(object sender, QEventArgs<QDragEnterEvent> e)
    {
      if (e.Event.MimeData.HasFormat("text/plain")) {
        e.Event.AcceptProposedAction();
      }
    }

    [Q_SLOT]
    private void mPasswordLineEdit_DragMoveEvent(object sender, QEventArgs<QDragMoveEvent> e)
    {
      if (e.Event.MimeData.HasFormat("text/plain")) {
        e.Event.AcceptProposedAction();
      }
    }

    [Q_SLOT]
    private void mPasswordLineEdit_DropEvent(object sender, QEventArgs<QDropEvent>  e)
    {
      if (e.Event.MimeData.HasFormat("text/plain")) {
        string strData = e.Event.MimeData.Text;
        if (strData == null) {
          Debug.Assert(false);
          return;
        }
        if (mPasswordLineEdit != null) {
          mPasswordLineEdit.Text = strData;
        }
        e.Event.AcceptProposedAction();
      }
    }
  }
}
