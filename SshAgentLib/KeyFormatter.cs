using System;
using System.Runtime.Serialization;
using System.Security;
using System.IO;
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
    /// <param name="aFileName">file containing SSH key data</param>
    /// <returns>key created from file data</returns>
    /// <exception cref="CallbackNullException">
    /// GetPassphraseCallbackMethod is null and aStream constrains encrypted key
    /// </exception>
    public ISshKey DeserializeFile(string aFileName)
    {
      using (FileStream stream =
        new FileStream(aFileName, FileMode.Open, FileAccess.Read)) {
        var key = Deserialize(stream) as ISshKey;
        if (string.IsNullOrEmpty(key.Comment)) {
          key.Comment = Path.GetFileName(aFileName);
        }
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
  }

  public static class KeyFormatterExt
  {
    /// <summary>
    /// Auto-detect data format, read data and create key object
    /// </summary>
    /// <param name="aStream"></param>
    /// <returns></returns>
    public static ISshKey ReadSshKey(this Stream aStream, KeyFormatter.GetPassphraseCallback aGetPassphraseCallback = null)
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
