using System;
using System.Runtime.Serialization;
using System.Security;
using System.IO;

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
      using (FileStream stream = new FileStream(aFileName, FileMode.CreateNew, FileAccess.Write)) {
        Serialize(stream, aObject);
      }
    }

    public abstract object Deserialize(Stream aStream);

    public ISshKey DeserializeFile(string aFileName)
    {
      using (FileStream stream =
        new FileStream(aFileName, FileMode.Open, FileAccess.Read)) {
        return (ISshKey)Deserialize(stream);
      }
    }

    public ISshKey Deserialize(byte[] aBytes)
    {
      using (MemoryStream stream = new MemoryStream(aBytes)) {
        return (ISshKey)Deserialize(stream);
      }
    }

  }
}
