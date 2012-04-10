using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;


namespace dlech.PageantSharp
{
	/// <summary>
	/// PageantSharp utility class.
	/// </summary>
	public static class PSUtil
	{

		/// <summary>
		/// Convert 32 bit integer to four bytes in BigEndian order
		/// </summary>
		/// <param name="i">integer to convert</param>
		/// <returns>four bytes</returns>
		public static byte[] IntToBytes(int i)
		{
			byte[] result = BitConverter.GetBytes(i);
			if (BitConverter.IsLittleEndian) {
				return result.Reverse().ToArray();
			} else {
				return result;
			}
		}

		/// <summary>
		/// Converts 4 bytes in BigEndian order to 32 bit integer
		/// </summary>
		/// <param name="bytes">array of bytes</param>
		/// <param name="offset">the offset where to start reading the bytes</param>
		/// <returns>32 bit integer</returns>
		public static int BytesToInt(byte[] bytes, int offset)
		{
			if (bytes == null) {
				throw new ArgumentNullException("bytes");
			}
			byte[] wokingBytes = new byte[4];
			Array.Copy(bytes, offset, wokingBytes, 0, 4);
			if (BitConverter.IsLittleEndian) {
				wokingBytes = wokingBytes.Reverse().ToArray();
			}
			return BitConverter.ToInt32(wokingBytes, 0);
		}

		/// <summary>
		/// converts string of hexadecimal characters to a byte[]
		/// two characters are converted into one byte
		/// </summary>
		/// <param name="base16String">the string to convert</param>
		/// <returns>array containing the converted bytes</returns>
		/// <exception cref="NullArgumentException">thrown if base16String is null or empty</exception>
		/// <exception cref="ArgumentException">thrown if base16String does not contain an even number of characters
		/// or if the characters are not hexadecimal digits (0-9 and A-F or a-f)</exception>
		public static byte[] FromHex(string base16String)
		{
			return FromHex(base16String, null);
		}

		/// <summary>
		/// converts string of hexadecimal characters to a byte[]
		/// two characters are converted into one byte
		/// </summary>
		/// <param name="base16String">the string to convert</param>
		/// <param name="delimeter">the delimeter that is present between each pair of digits</param>
		/// <returns>array containing the converted bytes</returns>
		/// <exception cref="NullArgumentException">thrown if base16String is null or empty</exception>
		/// <exception cref="ArgumentException">thrown if base16String does not contain an even number of characters
		/// or if the characters are not hexadecimal digits (0-9 and A-F or a-f)</exception>
		public static byte[] FromHex(string base16String, string delimeter)
		{
			if (string.IsNullOrEmpty(base16String)) {
				throw new ArgumentNullException("base16String");
			}

			// remove delimeters
			if (!string.IsNullOrEmpty(delimeter)) {
				base16String = base16String.Replace(delimeter, string.Empty);
			}

			int stringLength = base16String.Length;

			if ((stringLength % 2) != 0) {
				throw new ArgumentException("must have even number of characters", "base16String");
			}
			if (Regex.IsMatch(base16String, "[^0-9A-Fa-f]")) {
				throw new ArgumentException("must contain only hex characters", "base16String");
			}

			byte[] result = new byte[stringLength / 2];
			for (int i = 0; i < stringLength; i += 2) {
				result[i / 2] = Convert.ToByte(base16String.Substring(i, 2), 16);
			}
			return result;
		}

		/// <summary>
		/// Converts array of bytes to a string of hexidecimal digits delimited by':'. Alpha digits will be lower case.
		/// </summary>
		/// <param name="bytes">the byte[] to convert</param>
		/// <returns>the resulting string</returns>
		public static string ToHex(byte[] bytes)
		{
			return ToHex(bytes, ":");
		}

		/// <summary>
		/// Converts array of bytes to a string of hexidecimal digits. Alpha digits will be lower case.
		/// </summary>
		/// <param name="bytes">the byte[] to convert</param>
		/// <param name="delimeter">a delimeter to insert inbetween each pair of digits</param>
		/// <returns>the resulting string</returns>
		public static string ToHex(byte[] bytes, string delimeter)
		{
			if (bytes == null) {
				throw new ArgumentNullException("bytes");
			}
			int length = bytes.Length;
			string[] strings = new string[length];
			for (int i = 0; i < length; i++) {
				strings[i] = string.Format("{0:x2}", bytes[i]);
			}
			return string.Join(delimeter, strings);
		}

		public static byte[] FromBase64(string base64String)
		{
			return FromBase64(Encoding.UTF8.GetBytes(base64String));
		}

		public static byte[] FromBase64(byte[] base64Data)
		{
			using (FromBase64Transform base64Transform = new FromBase64Transform()) {
				return GenericTransform(base64Transform, base64Data);
			}
		}


		public static byte[] ToBase64(byte[] binaryData)
		{
			using (ToBase64Transform base64Transform = new ToBase64Transform()) {
				return GenericTransform(base64Transform, binaryData);
			}
		}

		internal static byte[] GenericTransform(ICryptoTransform transform, byte[] data)
		{
			List<byte> byteList = new List<byte>();
			byte[] outputBytes;
			int inputLength = data.Length;
			int inputBlockSize = transform.InputBlockSize;
			if (typeof(FromBase64Transform).IsInstanceOfType(transform)) {
				// workaround for apparent bug where FromBase64Transform.InputBlockSize
				// returns 1 when it should return 4
				inputBlockSize = 4;
			}
			int inputOffset = 0;
			outputBytes = new byte[transform.OutputBlockSize];
			if (!transform.CanTransformMultipleBlocks) {
				while (inputLength - inputOffset > inputBlockSize) {
					transform.TransformBlock(data, inputOffset, inputBlockSize,
						outputBytes, 0);
					byteList.AddRange(outputBytes);
					inputOffset += inputBlockSize;
				}
			}
			outputBytes = transform.TransformFinalBlock(data, inputOffset, inputLength - inputOffset);
			byteList.AddRange(outputBytes);
			byte[] result = byteList.ToArray();
			ClearByteList(byteList);
			return result;
		}

		/// <summary>
		/// writes over all values in list with 0 then call list.Clear()
		/// </summary>
		/// <param name="list">list to be cleared</param>
		public static void ClearByteList(List<byte> list)
		{
			int length = list.Count;
			for (int i = 0; i < length; i++) {
				list[i] = 0;
			}
			list.Clear();
		}

		/// <summary>
		/// removes leading element from array if the value of that element is 0
		/// </summary>
		/// <param name="array"></param>
		public static void TrimLeadingZero(PinnedByteArray array)
		{
			if (array != null && array.Data != null && array.Data.Length > 0) {
				if (array.Data[0] == 0) {
					PinnedByteArray arrayCopy = (PinnedByteArray)array.Clone();
					array.Data = new byte[array.Data.Length - 1];
					Array.Copy(arrayCopy.Data, 1, array.Data, 0, array.Data.Length);
					arrayCopy.Dispose();
				}
			}
		}


		/// <summary>
		/// Compuutes a % (b -1) of 2 large numbers
		/// </summary>
		/// <param name="a">variable a</param>
		/// <param name="b">variable b</param>
		/// <returns></returns>
		public static PinnedByteArray ModMinusOne(PinnedByteArray a, PinnedByteArray b)
		{
			using (PinnedByteArray bMinusOne = (PinnedByteArray)b.Clone()) {

				PinnedByteArray result = (PinnedByteArray)a.Clone();
				// should't have to worry about borrowing because b should be prime and therefore not end in zero
				bMinusOne.Data[bMinusOne.Data.Length - 1]--;
				int bShift = a.Data.Length - b.Data.Length;

				while (bShift >= 0) {
					while (CompareBigInt(result.Data, bMinusOne.Data, bShift) >= 0) {
						result.Data = SubtractBigInt(result.Data, bMinusOne.Data, bShift);
						TrimLeadingZero(result);
					}
					bShift--;
				}

				return result;
			}
		}

		/// <summary>
		/// Compares to BigInts
		/// </summary>
		/// <param name="a">variable a</param>
		/// <param name="b">variable b</param>
		/// <param name="bShift">number of bytes to shift b to the left</param>
		/// <returns>-1 if a &lt; b, 0 if a = b, 1 if a &gt; b</returns>
		private static int CompareBigInt(byte[] a, byte[] b, int bShift)
		{
			if (a.Length == b.Length + bShift) {
				for (int i=0; i < a.Length; i++) {
					int result = a[i].CompareTo((byte)((i < b.Length) ? b[i] : 0));
					if (result != 0) {
						return result;
					}
				}
				return 0;
			} else {
				return a.Length.CompareTo(b.Length + bShift);
			}
		}

		/// <summary>
		/// Compute a - b, assumes that a &gt; b&lt;&lt;bShift
		/// </summary>
		/// <param name="a">variable a</param>
		/// <param name="b">variable b</param>
		/// <param name="bShift"> number of bytes to shift b to the left</param>
		/// <returns>a - b</returns>
		private static byte[] SubtractBigInt(byte[] a, byte[] b, int bShift)
		{
			byte[] result = new byte[a.Length];
			byte[] borrow = new byte[a.Length + 1];

			int bOffset = a.Length - b.Length - bShift;

			for (int i=a.Length - 1; i >= 0; i--) {
				int diff  = a[i] - (((i < bOffset) || (i >= b.Length + bOffset)) ? 0 : b[i - bOffset]) - borrow[i + 1];
				while (diff < 0) {
					borrow[i] += 1;
					diff += byte.MaxValue + 1;
				}
				result[i] = (byte)diff;
			}
			return result;
		}

	}
}
