using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;

namespace dlech.PageantSharp
{
  /// <summary>
  /// used to build blobs that are used for storing and sending keys
  /// in open-ssh/PuTTY format
  /// </summary>
  public class BlobBuilder
  {

    private List<byte> byteList;

    /// <summary>
    /// Gets current length of blob
    /// </summary>
    public int Length
    {
      get
      {
        return byteList.Count();
      }
    }

    /// <summary>
    /// Creates new instance of BlobBuilder
    /// </summary>
    public BlobBuilder()
    {
      byteList = new List<byte>();
    }


    ~BlobBuilder()
    {
      Clear();
    }

    /// <summary>
    /// Adds bytes to builder
    /// </summary>
    /// <param name="aBytes"></param>
    public void AddBytes(byte[] aBytes)
    {
      byteList.AddRange(aBytes);
    }

    public void AddInt(int aInt)
    {
      AddInt((UInt32)aInt);
    }

    public void AddInt(UInt32 aInt)
    {
      byteList.AddRange(aInt.ToBytes());
    }

    /// <summary>
    /// Adds a string to the blob
    /// </summary>
    /// <param name="str">the string to add</param>
    public void AddString(string str)
    {
      AddBlob(Encoding.UTF8.GetBytes(str));
    }

    /// <summary>
    /// Adds BigInteger to builder prefixed with size
    /// </summary>
    /// <param name="bigInt"></param>
    public void AddBigInt(BigInteger aBigInt)
    {
      byte[] bytes = aBigInt.ToByteArray();
      AddBlob(bytes);
    }

    /// <summary>
    /// Adds byte[] as-is to the blob
    /// </summary>
    /// <param name="blob"></param>
    public void AddBlob(byte[] blob)
    {
      byteList.AddRange(blob.Length.ToBytes());
      byteList.AddRange(blob);
    }
    
    /// <summary>
    /// Prepends header 
    /// </summary>
    /// <param name="aMessage">message number to include in header</param>
    /// <param name="aHeaderData">data to include in header</param>
    public void InsertHeader(Agent.Message aMessage, int aHeaderData)
    {
      byteList.InsertRange(0, aHeaderData.ToBytes());
      byteList.Insert(0, (byte)aMessage);
      byte[] blobLength = byteList.Count.ToBytes();
      byteList.InsertRange(0, blobLength);
    }

    /// <summary>
    /// Prepends header 
    /// </summary>
    /// <param name="aMessage">message number to include in header</param>
    public void InsertHeader(Agent.Message aMessage)
    {
      byte[] blobLength;
      if (byteList.Count > 0) {
        blobLength = byteList.Count.ToBytes();
        byteList.InsertRange(0, blobLength);
      }
      byteList.Insert(0, (byte)aMessage);
      blobLength = byteList.Count.ToBytes();
      byteList.InsertRange(0, blobLength);
    }

    /// <summary>
    /// Gets the resulting blob from the blob builder.
    /// </summary>
    /// <returns>byte[] containing the blob</returns>
    public byte[] GetBlob()
    {
      return byteList.ToArray();
    }

    public PinnedByteArray GetBlobAsPinnedByteArray()
    {
      return new PinnedByteArray(GetBlob());      
    }

    /// <summary>
    /// Writes 0 to all values, then clears list
    /// </summary>
    public void Clear()
    {
      PSUtil.ClearByteList(byteList);
    }


  }
}
