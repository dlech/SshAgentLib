using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;

namespace dlech.PageantSharp
{
	/// <summary>
	/// used to parse keys stored in .ppk file
	/// </summary>
	public class PpkKeyBlobParser : IEnumerator
	{
		private int dataLength;
		private byte[] data;
		private int index;
		private byte[] current;

		public PpkKeyBlobParser(byte[] data)
		{
			if (data == null) {
				throw new ArgumentNullException("data");
			}

			this.dataLength = data.Length;
			this.data = new byte[dataLength];
			Array.Copy(data, this.data, dataLength);
			Reset();
		}

		public object Current
		{
			get { return current; }
		}

		public byte[] CurrentData
		{
			get { return current; }
		}

		public bool MoveNext()
		{
			// read length of next data group
			if (index + 4 <= dataLength) {
				int length = PSUtil.BytesToInt(data, index);
				index += 4;
				// read data from group
				if ((length > 0) && (index + length <= dataLength)) {
					current = new byte[length];
					Array.Copy(data, index, current, 0, length);
					index += length;
					return true;
				}
			}
			current = null;
			return false;
		}

		public void Reset()
		{
			this.index = 0;
			MoveNext();
		}
	}
}
