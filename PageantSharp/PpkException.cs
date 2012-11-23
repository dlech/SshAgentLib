using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.PageantSharp
{
  /// <summary>
  /// Identifies errors encountered when reading .ppk files
  /// </summary>
  public class PpkException : Exception
  {
    /// <summary>
    /// Possible errors
    /// </summary>
    public enum ErrorType
    {
      /// <summary>
      /// File version is not supported
      /// </summary>
      FileVersion,

      /// <summary>
      /// Public key encryption algorithm is not valid
      /// </summary>
      PublicKeyEncryption,

      /// <summary>
      /// Private key encryption algorithm is not valid
      /// </summary>
      PrivateKeyEncryption,

      /// <summary>
      /// File format was not expected format. See message for more info.
      /// </summary>
      FileFormat,

      /// <summary>
      /// Passphrase is wrong or file is corrupt
      /// </summary>
      BadPassphrase,

      /// <summary>
      /// File is corrupted or has been tampered with
      /// </summary>
      FileCorrupt
    }

    public ErrorType Error { get; private set; }

    public PpkException(ErrorType err)
    {
      this.Error = err;
    }

    public PpkException(ErrorType err, string message)
      : base(message)
    {
      this.Error = err;
    }

    public PpkException(ErrorType err, string message, Exception innerException)
      : base(message, innerException) 
    {
      this.Error = err;
    }
  }
}
