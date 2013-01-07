using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Runtime.InteropServices;
using System.IO;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// used to parse open-ssh blobs
  /// </summary>
  public class BlobParser
  {
    public Stream Stream { get; private set; }

    public BlobParser(byte[] aBlob) : this(new MemoryStream(aBlob)) { }

    public BlobParser(Stream aStream)
    {
      if (aStream == null) {
        throw new ArgumentNullException("aStream");
      }
      Stream = aStream;
    }

    public byte ReadByte()
    {
      if (Stream.Length - Stream.Position < 1) {
        throw new Exception("Not enough data");
      }
      return (byte)Stream.ReadByte();
    }

    public UInt32 ReadInt()
    {
      byte[] dataLegthBytes = new byte[4];
      if (Stream.Length - Stream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      return dataLegthBytes.ToInt();
    }

    public UInt16 ReadShort()
    {
        byte[] dataLegthBytes = new byte[2];
        if (Stream.Length - Stream.Position < dataLegthBytes.Length)
        {
            throw new Exception("Not enough data");
        }
        Stream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
        return (ushort)((dataLegthBytes[0] << 8) + dataLegthBytes[1]); ;

    }
    public Agent.BlobHeader ReadHeader()
    {
      Agent.BlobHeader header = new Agent.BlobHeader();

      header.BlobLength = ReadInt();
      if (Stream.Length - Stream.Position < header.BlobLength) {
        throw new Exception("Not enough data");
      }
      header.Message = (Agent.Message)ReadByte();
      return header;
    }

    public string ReadString()
    {
      return Encoding.UTF8.GetString(ReadBlob().Data);
    }

    public PinnedByteArray ReadBlob()
    {
        return ReadBytes(ReadInt());
    }

    public PinnedByteArray ReadSsh1BigIntBlob()
    {
        return ReadBytes((ReadShort() + (uint)7) / 8);
    }

    public PinnedByteArray ReadBytes(UInt32 blobLength)
    {
        if (Stream.Length - Stream.Position < blobLength)
        {
            throw new Exception("Not enough data");
        }
        PinnedByteArray blob = new PinnedByteArray((int)blobLength);
        Stream.Read(blob.Data, 0, blob.Data.Length);
        return blob;
    }

  }
}
