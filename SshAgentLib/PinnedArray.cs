using System;
using System.Collections.Generic;
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
  public class PinnedArray<T> : IDisposable, ICloneable
  {
    private T[] mData;
    private GCHandle mGCHandle;
    private bool mDisposed;

    /// <summary>
    /// The array that is wrapped.
    /// </summary>
    public T[] Data {
      get {
        if (mDisposed) {
          throw new ObjectDisposedException(GetType().Name);
        }
        return mData;
      }
      set {
        Dispose();
        if (value == null) {
          mData = new T[0];
        } else {
          mData = value;
        }
        mGCHandle = GCHandle.Alloc(mData, GCHandleType.Pinned);
        mDisposed = false;
      }
    }

    /// <summary>
    /// wraps byte[] in new PinnedByteArray instance
    /// </summary>
    /// <param name="array">the T[] to wrap</param>
    public PinnedArray(T[] mArray)
    {
      Data = mArray;
    }

    /// <summary>
    /// creates new instance of PinnedByteArray with a new T[] of the specified length
    /// </summary>
    /// <param name="length">length of new T[]</param>
    public PinnedArray(int mLength)
    {
      Data = new T[mLength];
    }

    ~PinnedArray()
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
      return new PinnedArray<T>((T[])Data.Clone());
    }
  }
}
