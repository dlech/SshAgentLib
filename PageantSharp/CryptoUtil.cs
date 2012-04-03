using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;


namespace dlech.PageantSharp
{
	/// <summary>
	/// static methods for cryptography functions
	/// </summary>
	public static class CryptoUtil
	{

		public static byte[] DecodeBase64(string base64String)
		{
			return DecodeBase64(Encoding.UTF8.GetBytes(base64String));
		}

		public static byte[] DecodeBase64(byte[] base64Data)
		{
			FromBase64Transform base64Transform = new FromBase64Transform();
			List<byte> byteList = new List<byte>();
			byte[] outputBytes;
			int inputLength = base64Data.Length;
			int inputBlockSize = 4; // base64Transform.InputBlockSize; // for some reason InputBlockSize returns 1 
			int inputOffset = 0;
			outputBytes = new byte[base64Transform.OutputBlockSize];
			if (!base64Transform.CanTransformMultipleBlocks) {
				while (inputLength - inputOffset > inputBlockSize) {
					base64Transform.TransformBlock(base64Data, inputOffset, inputBlockSize,
						outputBytes, 0);
					byteList.AddRange(outputBytes);
					inputOffset += inputBlockSize;
				}
			}
			outputBytes = base64Transform.TransformFinalBlock(base64Data, inputOffset, inputLength - inputOffset);
			byteList.AddRange(outputBytes);
			
			base64Transform.Clear();

			return byteList.ToArray();
		}
		
		
		public static byte[] EncodeBase64(byte[] binaryData)
		{
			ToBase64Transform base64Transform = new ToBase64Transform();
			List<byte> base64ByteList = new List<byte>();
			byte[] outputBytes;
			int inputLength = binaryData.Length;
			int inputBlockSize = base64Transform.InputBlockSize;
			int inputOffset = 0;
			outputBytes = new byte[base64Transform.OutputBlockSize];
			if (!base64Transform.CanTransformMultipleBlocks) {
				while (inputLength - inputOffset > inputBlockSize) {
					base64Transform.TransformBlock(binaryData, inputOffset, inputBlockSize,
						outputBytes, 0);
					base64ByteList.AddRange(outputBytes);
					inputOffset += inputBlockSize;
				}
			}
			outputBytes = base64Transform.TransformFinalBlock(binaryData, inputOffset, inputLength - inputOffset);
			base64ByteList.AddRange(outputBytes);

			base64Transform.Clear();

			return base64ByteList.ToArray();
		}	
	}
}
