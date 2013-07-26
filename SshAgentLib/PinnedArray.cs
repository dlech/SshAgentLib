//
// PinnedArray.cs
//
// Author(s): David Lechner <david@lechnology.com>
//
// Copyright (c) 2012-2013 David Lechner
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
      if (mGCHandle.IsAllocated) {
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
