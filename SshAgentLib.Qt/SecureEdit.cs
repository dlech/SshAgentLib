using System;
using System.Security;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using QtCore;
using QtGui;

//using KeePassLib.Utility;

// Code from KeePass <http://keepass.info>

namespace dlech.SshAgentLib.QtAgent
{
  /// <summary>
  /// Secure edit control class. Supports storing passwords in an encrypted
  /// form in the process memory.
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
        if (mSecureString != null)
          return (uint)mSecureString.Length;
        return (uint)mAltSecureString.Data.Length / 2;
      }
    }

    public SecureString SecureString {
      get {
        return mSecureString;
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
    /// <param name="tbPasswordBox">Text box to link to.</param>
    /// <param name="bHidePassword">Initial protection flag.</param>
    public void Attach(QLineEdit tbPasswordBox, EventHandler evTextChanged,
      bool bHidePassword)
    {
      Debug.Assert(tbPasswordBox != null);
      if (tbPasswordBox == null)
        throw new ArgumentNullException("tbPasswordBox");

      this.Detach();

      mPasswordLineEdit = tbPasswordBox;
      mTextChangedEventHandler = evTextChanged;

      // Initialize to zero-length string
      mPasswordLineEdit.Text = string.Empty;

      if (mSecureString != null) {
        mSecureString.Clear();
      } else {
        mAltSecureString.Clear();
        mAltSecureString.Data = new char[0];
      }

      EnableProtection(bHidePassword);

      if (mTextChangedEventHandler != null)
        mTextChangedEventHandler(mPasswordLineEdit, EventArgs.Empty);

      if (!mSecureDesktop)
        mPasswordLineEdit.AcceptDrops = true;

      // Register event handler
      mPasswordLineEdit.TextChanged += OnPasswordTextChanged;
      mPasswordLineEdit.FocusInEvent += OnGotFocus;
      if (!mSecureDesktop) {
        mPasswordLineEdit.DragEnterEvent += OnDragCheck;
        //m_tbPassword.DragMoveEvent += this.OnDragCheck;
        mPasswordLineEdit.DropEvent += OnDragDrop;
      }
    }

    /// <summary>
    /// Remove the current association. You should call this before the
    /// text box is destroyed.
    /// </summary>
    public void Detach()
    {
      if (mPasswordLineEdit != null) {
        mPasswordLineEdit.TextChanged -= OnPasswordTextChanged;
        mPasswordLineEdit.FocusInEvent -= OnGotFocus;
        if (!mSecureDesktop) {
          mPasswordLineEdit.DragEnterEvent -= this.OnDragCheck;
          //m_tbPassword.DragMoveEvent -= this.OnDragCheck;
          mPasswordLineEdit.DropEvent -= OnDragDrop;
        }

        mPasswordLineEdit = null;
      }
    }

    public void EnableProtection(bool bEnable)
    {
      if (mPasswordLineEdit == null) {
        Debug.Assert(false);
        return;
      }

      var echoMode = bEnable ? QLineEdit.EchoMode.Password :
        QLineEdit.EchoMode.Normal;
      if (mPasswordLineEdit.echoMode == echoMode)
        return;
      mPasswordLineEdit.echoMode = echoMode;

      ShowCurrentPassword(mPasswordLineEdit.HasSelectedText ?
                            mPasswordLineEdit.SelectionStart :
                            mPasswordLineEdit.CursorPosition,
                          mPasswordLineEdit.HasSelectedText ?
                            mPasswordLineEdit.SelectedText.Length : 0
      );
    }

    [Q_SLOT]
    private void OnPasswordTextChanged(string aText)
    {
      if (mPasswordLineEdit == null) {
        Debug.Assert(false);
        return;
      }

      if (mBlockTextChanged)
        return;

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

      int inxLeft = -1, inxRight = 0;
      StringBuilder sbNewPart = new StringBuilder();

      for (int i = 0; i < strText.Length; ++i) {
        if (strText[i] != cPasswordChar) {
          if (inxLeft == -1)
            inxLeft = i;
          inxRight = i;

          sbNewPart.Append(strText[i]);
        }
      }

      if (inxLeft < 0)
        RemoveInsert(nSelPos, strText.Length - nSelPos, string.Empty);
      else
        RemoveInsert(inxLeft, strText.Length - inxRight - 1,
          sbNewPart.ToString());

      ShowCurrentPassword(nSelPos, nSelLen);

      // Check for m_tbPassword being null from on now; the
      // control might be disposed already (by the user handler
      // triggered by the ShowCurrentPassword call)
//      if (m_tbPassword != null)
      // TODO - override undo?
//        m_tbPassword.ClearUndo() // Would need special undo buffer
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
        mPasswordLineEdit.Text = new string(cPasswordChar, mAltSecureString.Data.Length);
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
        for (int i = 0; i < mSecureString.Length; ++i)
          vChars[i] = (char)Marshal.ReadInt16(p, i * 2);
        Marshal.ZeroFreeGlobalAllocUnicode(p);

        byte[] pb = Encoding.UTF8.GetBytes(vChars);
        Array.Clear(vChars, 0, vChars.Length);

        return pb;
      } else
        return Encoding.UTF8.GetBytes(mAltSecureString.Data);
    }

    // temporary for debugging
    private string GetAsString()
    {
      if (mSecureString != null) {
        IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(mSecureString);
        string str = Marshal.PtrToStringUni(p);
        Marshal.ZeroFreeGlobalAllocUnicode(p);

        return str;
      } else
        return Encoding.Unicode.GetString(Encoding.Unicode.GetBytes(mAltSecureString.Data));
    }

    private void RemoveInsert(int nLeftRem, int nRightRem, string strInsert)
    {
      Debug.Assert(nLeftRem >= 0);

      if (mSecureString != null) {
        while (mSecureString.Length > (nLeftRem + nRightRem))
          mSecureString.RemoveAt(nLeftRem);

        for (int i = 0; i < strInsert.Length; ++i) {
          mSecureString.InsertAt(nLeftRem + i, strInsert[i]);
        }
      } else {
        using (var newString =
          new PinnedArray<char>(nLeftRem + nRightRem + strInsert.Length)) {
          Array.Copy(mAltSecureString.Data, newString.Data, nLeftRem);
          using (var insertString =
                 new PinnedArray<char>(Encoding.Unicode.GetChars(
                   Encoding.Unicode.GetBytes(strInsert)))) {
            Array.Copy(insertString.Data, 0, newString.Data, nLeftRem,
                       insertString.Data.Length);
            Array.Copy(mAltSecureString.Data,
                       mAltSecureString.Data.Length - nRightRem,
                       newString.Data, nLeftRem + insertString.Data.Length,
                       nRightRem);
          }
          mAltSecureString.Clear();
          mAltSecureString = newString.Clone() as PinnedArray<char>;
        }
        var pw = GetAsString();
        Console.Error.WriteLine(string.Format("{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}",
                                                nLeftRem,
                                                nRightRem,
                                                strInsert,
                                                strInsert.Length,
                                                pw,
                                                pw.Length,
                                              mPasswordLineEdit.Text,
                                              mPasswordLineEdit.Text.Length)
        );
      }
    }

    public bool ContentsEqualTo(SecureEdit secOther)
    {
      Debug.Assert(secOther != null);
      if (secOther == null)
        return false;

      byte[] pbThis = this.ToUtf8();
      byte[] pbOther = secOther.ToUtf8();

      bool bEqual = true;

      if (pbThis.Length != pbOther.Length)
        bEqual = false;
      else {
        for (int i = 0; i < pbThis.Length; ++i) {
          if (pbThis[i] != pbOther[i]) {
            bEqual = false;
            break;
          }
        }
      }

      Array.Clear(pbThis, 0, pbThis.Length);
      Array.Clear(pbOther, 0, pbOther.Length);
      return bEqual;
    }

    public void SetPassword(byte[] pbUtf8)
    {
      Debug.Assert(pbUtf8 != null);
      if (pbUtf8 == null)
        throw new ArgumentNullException("pbUtf8");

      if (mSecureString != null) {
        mSecureString.Clear();

        char[] vChars = Encoding.UTF8.GetChars(pbUtf8);

        for (int i = 0; i < vChars.Length; ++i) {
          mSecureString.AppendChar(vChars[i]);
          vChars[i] = char.MinValue;
        }
      } else
        mAltSecureString.Data = Encoding.UTF8.GetChars(pbUtf8);

      ShowCurrentPassword(0, 0);
    }

    [Q_SLOT]
    private void OnGotFocus(object sender, EventArgs e)
    {
      if (mPasswordLineEdit == null) {
        Debug.Assert(false);
        return;
      }

      if (mFirstGotFocus && (mPasswordLineEdit != null))
        mPasswordLineEdit.SelectAll();

      mFirstGotFocus = false;
    }

    [Q_SLOT]
    private void OnDragCheck(object sender, QEventArgs<QDragEnterEvent> e)
    {
      if (e.Event.MimeData.HasFormat("text/plain")) {
        e.Event.AcceptProposedAction();
      }
    }

    private void OnDragDrop(object sender, QEventArgs<QDropEvent>  e)
    {
      if (e.Event.MimeData.HasFormat("text/plain")) {
        string strData = e.Event.MimeData.Text;
        if (strData == null) {
          Debug.Assert(false);
          return;
        }
        if (mPasswordLineEdit != null)
          mPasswordLineEdit.Text = strData;
        e.Event.AcceptProposedAction();
      }
    }
  }
}
