using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Runtime.InteropServices;
using System.IO;

namespace dlech.PageantSharp
{
  /// <summary>
  /// used to parse open-ssh blobs
  /// </summary>
  public class BlobParser
  {
    private Stream mStream;

    public BlobParser(byte[] aBlob) : this(new MemoryStream(aBlob)) { }

    public BlobParser(Stream aStream)
    {
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }
      mStream = aStream;
    }

    public byte ReadByte()
    {
      if (mStream.Length - mStream.Position < 1) {
        throw new Exception("Not enough data");
      }
      return (byte)mStream.ReadByte();
    }

    public UInt32 ReadInt()
    {
      byte[] dataLegthBytes = new byte[4];
      if (mStream.Length - mStream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      mStream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      return dataLegthBytes.ToInt();
    }

    public OpenSsh.BlobHeader ReadHeader()
    {
      OpenSsh.BlobHeader header = new OpenSsh.BlobHeader();

      header.BlobLength = ReadInt();
      if (mStream.Length - mStream.Position < header.BlobLength) {
        throw new Exception("Not enough data");
      }      
      header.Message = (OpenSsh.Message)ReadByte();
      return header;
    }

    public string ReadString()
    {
      return Encoding.UTF8.GetString(ReadBlob().Data);
    }

    public PinnedByteArray ReadBlob()
    {
      UInt32 blobLength = ReadInt();
      if (mStream.Length - mStream.Position < blobLength) {
        throw new Exception("Not enough data");
      }
      PinnedByteArray blob = new PinnedByteArray((int)blobLength);
      mStream.Read(blob.Data, 0, blob.Data.Length);
      return blob;
    }

  }
}
