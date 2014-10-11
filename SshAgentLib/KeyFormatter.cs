//
// BlobParser.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2014 David Lechner
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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace dlech.SshAgentLib
{
  public abstract class KeyFormatter : IFormatter
  {

    /// <summary>
    /// Gets passphrase.
    /// </summary>
    /// <returns>the passphrase</returns>
    public delegate SecureString GetPassphraseCallback(string comment);

    public SerializationBinder Binder { get; set; }

    public StreamingContext Context { get; set; }

    public ISurrogateSelector SurrogateSelector { get; set; }

    /// <summary>
    /// Method that implements GetPassphraseCallback.
    /// </summary>
    /// <remarks>
    /// Only required if the key data deserialization data is encrypted and
    /// requires a passphrase or the serialization data is to be encrypted
    /// </remarks>
    public GetPassphraseCallback GetPassphraseCallbackMethod { get; set; }

    /// <summary>
    /// Serialize ISshKey to stream
    /// </summary>
    /// <param name="aStream">target stream</param>
    /// <param name="aObject">ISshKey object</param>
    public abstract void Serialize(Stream aStream, object aObject);

    /// <summary>
    /// Serialize ISshKey to file
    /// </summary>
    /// <param name="aKey">the key to serialize</param>
    /// <param name="aFileName">target file</param>
    public void SerializeToFile(ISshKey aKey, string aFileName)
    {
      using (FileStream stream = new FileStream(aFileName, FileMode.CreateNew,
        FileAccess.Write)) {

        Serialize(stream, aKey);
      }
    }

    /// <summary>
    /// Parse stream containing SSH key data
    /// </summary>
    /// <param name="aStream">stream containing SSH key data</param>
    /// <returns>ISshKey key created from stream data</returns>
    /// <exception cref="CallbackNullException">
    /// GetPassphraseCallbackMethod is null and aStream constrains encrypted key
    /// </exception>
    public abstract object Deserialize(Stream aStream);

    /// <summary>
    /// Read file containing SSH key data
    /// </summary>
    /// <param name="fileName">file containing SSH key data</param>
    /// <returns>key created from file data</returns>
    /// <exception cref="CallbackNullException">
    /// GetPassphraseCallbackMethod is null and aStream constrains encrypted key
    /// </exception>
    public ISshKey DeserializeFile(string fileName)
    {
      using (FileStream stream =
        new FileStream(fileName, FileMode.Open, FileAccess.Read)) {
        var key = Deserialize(stream) as ISshKey;
        if (string.IsNullOrEmpty(key.Comment)) {
          try {
            var pubFile = fileName + ".pub";
            if (File.Exists(pubFile)) {
              var lines = File.ReadAllLines(pubFile, Encoding.UTF8);
              key.Comment = GetComment (lines);
            }
          } catch (Exception) {
            // don't worry about it
          }
        }
        key.Source = fileName;
        return key;
      }
    }

    /// <summary>
    /// Parse byte[] containing SSH key data
    /// </summary>
    /// <param name="aBytes">byte[] containing SSH key data</param>
    /// <returns>key created from file data</returns>
    /// <exception cref="CallbackNullException">
    /// GetPassphraseCallbackMethod is null and aStream constrains encrypted key
    /// </exception>
    public ISshKey Deserialize(byte[] aBytes)
    {
      using (MemoryStream stream = new MemoryStream(aBytes)) {
        return (ISshKey)Deserialize(stream);
      }
    }

    /// <summary>
    /// Attempts to return a Formatter that can deserialize data given the
    /// specified first line
    /// </summary>
    /// <param name="aFirstLine">first line of data to be deserialized</param>
    /// <returns>
    /// KeyFormatter that should be able to deserialize the data
    /// </returns>
    /// <exception cref="KeyFormatterException">
    /// The file format was not recognized
    /// </exception>
    public static KeyFormatter GetFormatter (string aFirstLine)
    {
      // PuTTY Private key format
      var ppkRegex = new Regex ("PuTTY-User-Key-File-[12]");
      // OpenSSH private key format
      var pemPrivateKeyRegex = new Regex ("-----BEGIN .* PRIVATE KEY-----");

      if (!string.IsNullOrWhiteSpace (aFirstLine)) {
        if (ppkRegex.IsMatch (aFirstLine)) {
          return new PpkFormatter ();
        } else if (pemPrivateKeyRegex.IsMatch (aFirstLine)) {
          return new Ssh2KeyFormatter ();
        } else if (Ssh1KeyFormatter.FILE_HEADER_LINE.Equals (aFirstLine)) {
          return new Ssh1KeyFormatter ();
        }
      }
      throw new KeyFormatterException ("Unknown file format");
    }

    public static string GetComment(IEnumerable<string> publicKeyFileLines, string defaultValue = null)
    {
      const string rfc4716BeginMarker = "---- BEGIN SSH2 PUBLIC KEY ----";
      const string rfc4716CommentHeader = "Comment: ";
      const string openSshPublicKeyStart = "ssh-";
      string comment = null;

      if (publicKeyFileLines == null)
        throw new ArgumentNullException("publicKeyFileLines");
      var firstLine = publicKeyFileLines.FirstOrDefault();
      if (firstLine != null) {
        if (firstLine == rfc4716BeginMarker) {
          var commentFound = false;
          foreach (var line in publicKeyFileLines) {
            if (commentFound) {
              comment += line;
            } else if (line.StartsWith(rfc4716CommentHeader)) {
              commentFound = true;
              comment = line.Substring(rfc4716CommentHeader.Length);
            }
            if (!commentFound)
              continue;
            if (comment.EndsWith("\\")) {
              comment = comment.Substring(0, comment.Length - 1);
              continue;
            }
          }
          if (comment == null)
            return defaultValue;
          if (comment.StartsWith("\"") && comment.EndsWith("\"")) {
            comment = comment.Substring(1, comment.Length - 2);
          }
          return comment;
        } else if (firstLine.StartsWith(openSshPublicKeyStart)) {
          var item = firstLine.Split(new char[] { ' ' }, 3);
          if (item.Length == 3)
            return item[2];
        }
      }
      return defaultValue;
    }
  }

  public static class KeyFormatterExt
  {
    /// <summary>
    /// Auto-detect data format, read data and create key object
    /// </summary>
    /// <param name="aStream"></param>
    /// <returns></returns>
    public static ISshKey ReadSshKey(this Stream aStream,
                                     KeyFormatter.GetPassphraseCallback aGetPassphraseCallback = null)
    {
      using (var reader = new StreamReader(aStream)) {
        var firstLine = reader.ReadLine();
        var formatter = KeyFormatter.GetFormatter(firstLine);
        formatter.GetPassphraseCallbackMethod = aGetPassphraseCallback;
        aStream.Position = 0;
        return formatter.Deserialize(aStream) as ISshKey;
      }
    }

    /// <summary>
    /// Auto-detect data format, read data and create key object
    /// </summary>
    /// <param name="aStream"></param>
    /// <returns></returns>
    public static ISshKey ReadSshKey(this byte[] aData, KeyFormatter.GetPassphraseCallback aGetPassphraseCallback = null)
    {
      using (var stream = new MemoryStream(aData)) {
        return stream.ReadSshKey(aGetPassphraseCallback);
      }
    }
  }
}
