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
    /// Gets passphrase. This method is only called if the file requires a passphrase.
    /// </summary>
    /// <returns></returns>
    public delegate SecureString GetPassphraseCallback();

    public SerializationBinder Binder { get; set; }

    public StreamingContext Context { get; set; }

    public ISurrogateSelector SurrogateSelector { get; set; }

    public GetPassphraseCallback GetPassphraseCallbackMethod { get; set; }

    public abstract void Serialize(Stream aStream, object aObject);

    public void SerializeFile(object aObject, string aFileName)
    {
      using (FileStream stream = new FileStream(aFileName, FileMode.CreateNew,
        FileAccess.Write)) {

        Serialize(stream, aObject);
      }
    }

    public abstract object Deserialize(Stream aStream);

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
    /// <returns>KeyFormatter that should be able to deserialize the data</returns>
    public static KeyFormatter GetFormatter(string aFirstLine)
    {
      var ppkRegex = new Regex("PuTTY-User-Key-File-[12]");
      var pemPrivateKeyRegex = new Regex("-----BEGIN .* PRIVATE KEY-----");

      if (ppkRegex.IsMatch(aFirstLine)) {
        return new PpkFormatter();
      } else if (pemPrivateKeyRegex.IsMatch(aFirstLine)) {
        return new Ssh2KeyFormatter();
      } else {
        throw new Exception("Unknown format");
      }
    }
  }
}
