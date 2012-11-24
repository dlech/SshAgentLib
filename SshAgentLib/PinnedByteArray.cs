using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Wrapper for byte[] when it used for sensitive data. 
  /// 
  /// Data is pinned in memory so that extra copies are not made
  /// by the garbage collector.
  /// 
  /// Data is cleared (values set to 0) when object is disposed.
  /// </summary>
  public class PinnedByteArray : IDisposable, ICloneable
  {
    private byte[] mData;
    private GCHandle mGCHandle;
    private bool mDisposed;

    /// <summary>
    /// The array that is wrapped.
    /// </summary>
    public byte[] Data {
      get {
        if (mDisposed) {
          throw new ObjectDisposedException(GetType().Name);
        }
        return mData;
      }
      set {
        Dispose();
        mData = value;
        mGCHandle = GCHandle.Alloc(mData, GCHandleType.Pinned);        
        mDisposed = false;
      }
    }

    /// <summary>
    /// wraps byte[] in new PinnedByteArray instance
    /// </summary>
    /// <param name="array">the byte[] to wrap</param>
    public PinnedByteArray(byte[] mArray)
    {
      Data = mArray;
    }

    /// <summary>
    /// creates new instance of PinnedByteArray with a new byte[] of the specified length
    /// </summary>
    /// <param name="length">length of new byte[]</param>
    public PinnedByteArray(int mLength)
    {
      Data = new byte[mLength];
    }
        
    ~PinnedByteArray()
    {     
      Dispose();
    }

    /// <summary>
    /// Sets all array values to 0
    /// </summary>
    public void Clear()
    {
      if (this.mData != null) {
        Array.Clear(mData, 0, mData.Length);
      }
    }
    
    /// <summary>
    /// Calls Clear() and unpins memory
    /// </summary>
    public void Dispose()
    {
      Clear();
      if (mGCHandle != null && mGCHandle.IsAllocated) {
        mGCHandle.Free();
      }
      mDisposed = true;
    }

    public object Clone()
    {
      return new PinnedByteArray((byte[])Data.Clone());
    }
  }
}
