//
// PpkFormatterException.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Identifies errors encountered when reading .ppk files
  /// </summary>
  public class PpkFormatterException : KeyFormatterException
  {
    /// <summary>
    /// Possible errors
    /// </summary>
    public enum PpkErrorType
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
      /// Private key is encrypted, but there is no passphrase supplied
      /// </summary>
      MissingPassphrase,

      /// <summary>
      /// A passphrase is supplied when the private key is unprotected
      /// </summary>
      NotEncrypted,

      /// <summary>
      /// File is corrupted or has been tampered with
      /// </summary>
      FileCorrupt
    }

    public PpkErrorType PpkError { get; private set; }

    public PpkFormatterException(PpkErrorType err)
    {
      this.PpkError = err;
    }

    public PpkFormatterException(PpkErrorType err, string message)
      : base(message)
    {
      this.PpkError = err;
    }

    public PpkFormatterException(PpkErrorType err, string message,
      Exception innerException)
      : base(message, innerException)
    {
      this.PpkError = err;
    }
  }
}
