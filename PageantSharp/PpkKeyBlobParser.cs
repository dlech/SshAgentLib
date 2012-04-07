using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Runtime.InteropServices;

namespace dlech.PageantSharp
{
	/// <summary>
	/// used to parse keys stored in .ppk file
	/// </summary>
	public class PpkKeyBlobParser : IEnumerator, IDisposable
	{
		private int dataLength;
		private PinnedByteArray dataArray;
		private int index;
		private PinnedByteArray currentArray;

		/// <summary>
		/// Gets current data segment as object.
		/// Objects returned by this property should be manually disposed 
		/// as soon as they are no longer needed.
		/// </summary>
		public object Current
		{
			get { return currentArray; }
		}

		/// <summary>
		/// Gets current data segment as PinnedByteArray.
		/// Objects returned by this property should be manually disposed 
		/// as soon as they are no longer needed.
		/// </summary>
		public PinnedByteArray CurrentAsPinnedByteArray
		{
			get { return currentArray; }
		}

		public PpkKeyBlobParser(byte[] data)
		{
			if (data == null) {
				throw new ArgumentNullException("data");
			}

			this.dataLength = data.Length;
			this.dataArray = new PinnedByteArray(dataLength);
			// we will be working with a copy so that data cannot be changed exteranally
			Array.Copy(data, this.dataArray.Data, dataLength);
			Reset();
		}

		~PpkKeyBlobParser()
		{
			Dispose();
		}	

		public void Dispose()
		{
			if (dataArray != null) {
				dataArray.Dispose();
			}
		}				

		public bool MoveNext()
		{
			// read length of next data group
			if (index + 4 <= dataLength) {
				int length = PSUtil.BytesToInt(dataArray.Data, index);
				index += 4;
				// read data from group
				if ((length > 0) && (index + length <= dataLength)) {
					currentArray = new PinnedByteArray(length);
					Array.Copy(dataArray.Data, index, currentArray.Data, 0, length);
					index += length;
					return true;
				}
			}
			currentArray = null;
			return false;
		}

		public void Reset()
		{
			this.index = 0;
			MoveNext();
		}
		
	}
}
