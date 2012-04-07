using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace dlech.PageantSharp
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
		private byte[] data;
		private GCHandle gcHandle;

		/// <summary>
		/// The array that is wrapped.
		/// </summary>
		public byte[] Data
		{
			get
			{
				return data;
			}
			set
			{
				Dispose();
				this.data = value;
				this.gcHandle = GCHandle.Alloc(this.data, GCHandleType.Pinned);
			}
		}

		/// <summary>
		/// wraps byte[] in new PinnedByteArray instance
		/// </summary>
		/// <param name="array">the byte[] to wrap</param>
		public PinnedByteArray(byte[] array)
		{
			Data = array;
		}

		/// <summary>
		/// creates new instance of PinnedByteArray with a new byte[] of the specified length
		/// </summary>
		/// <param name="length">length of new byte[]</param>
		public PinnedByteArray(int length)
		{
			Data = new byte[length];
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
			if (this.data != null) {
				Array.Clear(this.data, 0, this.data.Length);
			}
		}
		
		/// <summary>
		/// Calls Clear() and unpins memory
		/// </summary>
		public void Dispose()
		{
			Clear();
			if (this.gcHandle != null && this.gcHandle.IsAllocated) {
				this.gcHandle.Free();
			}
		}

		public object Clone()
		{
			return new PinnedByteArray((byte[])this.Data.Clone());
		}
	}
}
