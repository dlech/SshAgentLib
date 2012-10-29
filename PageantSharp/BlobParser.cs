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
    
    public OpenSsh.BlobHeader ReadHeader()
    {
      OpenSsh.BlobHeader header = new OpenSsh.BlobHeader();

      byte[] dataLegthBytes = new byte[4];
      if (mStream.Length - mStream.Position < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      mStream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      header.BlobLength = PSUtil.BytesToInt(dataLegthBytes, 0);

      if (mStream.Length - mStream.Position < header.BlobLength) {
        throw new Exception("Not enough data");
      }      
      header.Message = (OpenSsh.Message)mStream.ReadByte();
      return header;
    }

    public PinnedByteArray Read()
    {
      byte[] dataLegthBytes = new byte[4];
      if (mStream.Length - mStream.Position  < dataLegthBytes.Length) {
        throw new Exception("Not enough data");
      }
      mStream.Read(dataLegthBytes, 0, dataLegthBytes.Length);
      int blobLength = PSUtil.BytesToInt(dataLegthBytes, 0);
      if (mStream.Length - mStream.Position < blobLength) {
        throw new Exception("Not enough data");
      }
      PinnedByteArray blob = new PinnedByteArray(blobLength);
      mStream.Read(blob.Data, 0, blob.Data.Length);
      return blob;
    }

  }
}
