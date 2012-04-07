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
		/// Converts array of bytes to a string of hexidecimal digits. Alpha digits will be lower case.
		/// </summary>
		/// <param name="bytes">the byte[] to convert</param>
		/// <returns>the resulting string</returns>
		public static string ToHex(byte[] bytes)
		{
			return ToHex(bytes, null);
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
			FromBase64Transform base64Transform = new FromBase64Transform();
			GenericTransform(base64Transform, ref base64Data);
			base64Transform.Clear();
			return base64Data;
		}


		public static byte[] ToBase64(byte[] binaryData)
		{
			ToBase64Transform base64Transform = new ToBase64Transform();
			GenericTransform(base64Transform, ref binaryData);
			base64Transform.Clear();
			return binaryData;
		}

		internal static void GenericTransform(ICryptoTransform transform, ref byte[] data)
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
			Array.Clear(data, 0, data.Length);
			data = byteList.ToArray();
			ClearByteList(byteList);			
		}

		/// <summary>
		/// writes over all values in list with 0 then call list.Clear()
		/// </summary>
		/// <param name="list">list to be cleared</param>
		public static void ClearByteList(List<byte> list)
		{
			int length = list.Count;
			for (int i = 0; i< length; i++) {
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
	}
}
