using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.PageantSharp
{
	/// <summary>
	/// used to build blobs that are used for storing and sending keys in PuTTY format
	/// </summary>
	public sealed class PpkKeyBlobBuilder 
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
		/// Creates new instance of PpkBlobBuilder
		/// </summary>
		public PpkKeyBlobBuilder()
		{
			byteList = new List<byte>();
		}


		~PpkKeyBlobBuilder()
		{
			Clear();
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
		/// Adds 0 pad to byte[] if required and adds the result to the blob
		/// </summary>
		/// <param name="bigInt"></param>
		public void AddBigInt(byte[] bigInt)
		{
			bool pad = (bigInt[0] & 0x80) == 0x80;
			byteList.AddRange(PSUtil.IntToBytes(bigInt.Length + (pad ? 1 : 0)));
			if (pad) {
				byteList.Add(0);
			}
			byteList.AddRange(bigInt);
			Array.Clear(bigInt, 0, bigInt.Length);
		}

		/// <summary>
		/// Adds byte[] as-is to the blob
		/// </summary>
		/// <param name="blob"></param>
		public void AddBlob(byte[] blob)
		{
			byteList.AddRange(PSUtil.IntToBytes(blob.Length));
			byteList.AddRange(blob);
		}

		/// <summary>
		/// Gets the resulting blob from the blob builder.
		/// </summary>
		/// <returns>byte[] containing the blob</returns>
		public byte[] getBlob()
		{
			return byteList.ToArray();
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
