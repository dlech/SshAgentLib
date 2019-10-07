//
// Util.cs
//
// Author(s): David Lechner <david@lechnology.com>
//            Max Laverse
//
// Copyright (c) 2012-2013,2017 David Lechner
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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// SshAgentLib utility class.
  /// </summary>
  public static class Util
  {

    static string assemblyTitle;

    /// <summary>
    /// Adds Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM constraint to key
    /// </summary>
    public static void AddConfirmConstraint(this ICollection<Agent.KeyConstraint> keyCollection)
    {
      var constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM;
      keyCollection.Add(constraint);
    }

    /// <summary>
    /// Adds Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME constraint to key
    /// </summary>
    public static void AddLifetimeConstraint(this ICollection<Agent.KeyConstraint> keyCollection, uint lifetime)
    {
      var constraint = new Agent.KeyConstraint();
      constraint.Type = Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME;
      constraint.Data = lifetime;
      keyCollection.Add(constraint);
    }

    /// <summary>
    /// Gets the Type of the Data object for a given Agent.KeyConstraintType
    /// </summary>
    /// <param name="aConstraint"></param>
    /// <returns></returns>
    public static Type GetDataType(this Agent.KeyConstraintType aConstraint)
    {
      switch (aConstraint) {
        case Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM:
          return null;
        case Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME:
          return typeof(uint);
        default:
          Debug.Fail("Unknown KeyConstraintType");
          throw new ArgumentException("Unknown KeyConstraintType");
      }
    }

    /// <summary>
    /// Writes aBuiler data to aStream at current position of aStream
    /// </summary>
    /// <param name="aStream">Stream to write to</param>
    /// <param name="aBuilder">BlobBuilder to use</param>
    public static void WriteBlob(this Stream aStream, BlobBuilder aBuilder)
    {
      aStream.Write(aBuilder.GetBlob(), 0, aBuilder.Length);
    }

    /// <summary>
    /// Convert 32 bit integer to four bytes in BigEndian order
    /// </summary>
    /// <param name="n">integer to convert</param>
    /// <returns>four bytes</returns>
    public static byte[] ToBytes(this int n)
    {
      return ((uint)n).ToBytes();
    }

    /// <summary>
    /// Convert 32 bit integer to four bytes in BigEndian order
    /// </summary>
    /// <param name="n">integer to convert</param>
    /// <returns>four bytes</returns>
    public static byte[] ToBytes(this uint n)
    {
      byte[] result = BitConverter.GetBytes(n);
      if (BitConverter.IsLittleEndian) {
        result = result.Reverse().ToArray();
      }
      return result;
    }

    /// <summary>
    /// Convert 64 bit integer to eight bytes in BigEndian order
    /// </summary>
    /// <param name="n">integer to convert</param>
    /// <returns>eight bytes</returns>
    public static byte[] ToBytes(this ulong n)
    {
      byte[] result = BitConverter.GetBytes(n);
      if (BitConverter.IsLittleEndian) {
        result = result.Reverse().ToArray();
      }
      return result;
    }

    /// <summary>
    /// Convert 64 bit integer to eight bytes in BigEndian order
    /// </summary>
    /// <param name="n">integer to convert</param>
    /// <returns>eight bytes</returns>
    public static byte[] ToBytes(this long n)
    {
      return ((ulong)n).ToBytes();
    }

    /// <summary>
    /// Converts 4 bytes in BigEndian order to 32 bit integer
    /// </summary>
    /// <param name="bytes">array of bytes</param>
    /// <returns>32 bit integer</returns>
    public static uint ToUInt32(this byte[] bytes)
    {
      return bytes.ToUInt32(0);
    }

    /// <summary>
    /// Converts 4 bytes in BigEndian order to 32 bit integer
    /// </summary>
    /// <param name="bytes">array of bytes</param>
    /// <param name="offset">the offset where to start reading the bytes</param>
    /// <returns>32 bit integer</returns>
    public static uint ToUInt32(this byte[] bytes, int offset)
    {
      if (bytes == null) {
        throw new ArgumentNullException("bytes");
      }
      byte[] wokingBytes = new byte[4];
      Array.Copy(bytes, offset, wokingBytes, 0, 4);
      if (BitConverter.IsLittleEndian) {
        wokingBytes = wokingBytes.Reverse().ToArray();
      }
      return BitConverter.ToUInt32(wokingBytes, 0);
    }

    /// <summary>
    /// converts string of hexadecimal characters to a byte[]
    /// two characters are converted into one byte
    /// </summary>
    /// <param name="base16String">the string to convert</param>
    /// <returns>array containing the converted bytes</returns>
    /// <exception cref="ArgumentNullException">thrown if base16String is null or empty</exception>
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
    /// <param name="delimeter">the delimiter that is present between each pair of digits</param>
    /// <returns>array containing the converted bytes</returns>
    /// <exception cref="ArgumentNullException">thrown if base16String is null or empty</exception>
    /// <exception cref="ArgumentException">thrown if base16String does not contain an even number of characters
    /// or if the characters are not hexadecimal digits (0-9 and A-F or a-f)</exception>
    public static byte[] FromHex(string base16String, string delimeter)
    {
      if (string.IsNullOrEmpty(base16String)) {
        throw new ArgumentNullException("base16String");
      }

      // remove delimiters
      if (!string.IsNullOrEmpty(delimeter)) {
        base16String = base16String.Replace(delimeter, string.Empty);
      }

      int stringLength = base16String.Length;

      if ((stringLength % 2) != 0) {
        throw new ArgumentException("must have even number of characters",
                                    "base16String");
      }
      if (Regex.IsMatch(base16String, "[^0-9A-Fa-f]")) {
        throw new ArgumentException("must contain only hex characters",
                                    "base16String");
      }

      byte[] result = new byte[stringLength / 2];
      for (int i = 0; i < stringLength; i += 2) {
        result[i / 2] = Convert.ToByte(base16String.Substring(i, 2), 16);
      }
      return result;
    }

    /// <summary>
    /// Converts array of bytes to a string of hexadecimal digits delimited
    /// by':'. Alpha digits will be lower case.
    /// </summary>
    /// <param name="bytes">the byte[] to convert</param>
    /// <returns>the resulting string</returns>
    public static string ToHexString(this byte[] bytes)
    {
      return BitConverter.ToString(bytes).ToLowerInvariant().Replace("-", ":");
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

    public static byte[] ToBase64(this byte[] binaryData)
    {
      using (ToBase64Transform base64Transform = new ToBase64Transform()) {
        return GenericTransform(base64Transform, binaryData);
      }
    }

    internal static byte[] GenericTransform(ICryptoTransform transform,
                                            byte[] data)
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
      outputBytes = transform.TransformFinalBlock(data, inputOffset,
                                                  inputLength - inputOffset);
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

    static int Chmod(string path, int mode)
    {
      // This has to be in a separate method because on Windows we will get
      // a FileNotFoundException when the method is loaded if Mono is not present.
      return Mono.Unix.Native.Syscall.chmod(path, (Mono.Unix.Native.FilePermissions)mode);
    }

    /// <summary>
    /// Wrapper around Mono.Unix chmod.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="mode">The file mode.</param>
    public static bool TryChmod(string path, int mode)
    {
      try {
        var ret = Chmod(path, mode);
        return ret == 0;
      }
      catch {
        return false;
      }
    }

    /// <summary>
    /// Unicode char to to ANSI char.
    /// </summary>
    /// <returns>
    /// ANSI char.
    /// </returns>
    /// <param name='unicodeChar'>
    /// Unicode char.
    /// </param>
    /// <remarks>Based on http://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt </remarks>
    public static byte UnicodeToAnsi(this int unicodeChar)
    {
      switch (unicodeChar) {
        case 0x0000:
          return 0x00; //Null
        case 0x0001:
          return 0x01; //Start Of Heading
        case 0x0002:
          return 0x02; //Start Of Text
        case 0x0003:
          return 0x03; //End Of Text
        case 0x0004:
          return 0x04; //End Of Transmission
        case 0x0005:
          return 0x05; //Enquiry
        case 0x0006:
          return 0x06; //Acknowledge
        case 0x0007:
          return 0x07; //Bell
        case 0x0008:
          return 0x08; //Backspace
        case 0x0009:
          return 0x09; //Horizontal Tabulation
        case 0x000a:
          return 0x0a; //Line Feed
        case 0x000b:
          return 0x0b; //Vertical Tabulation
        case 0x000c:
          return 0x0c; //Form Feed
        case 0x000d:
          return 0x0d; //Carriage Return
        case 0x000e:
          return 0x0e; //Shift Out
        case 0x000f:
          return 0x0f; //Shift In
        case 0x0010:
          return 0x10; //Data Link Escape
        case 0x0011:
          return 0x11; //Device Control One
        case 0x0012:
          return 0x12; //Device Control Two
        case 0x0013:
          return 0x13; //Device Control Three
        case 0x0014:
          return 0x14; //Device Control Four
        case 0x0015:
          return 0x15; //Negative Acknowledge
        case 0x0016:
          return 0x16; //Synchronous Idle
        case 0x0017:
          return 0x17; //End Of Transmission Block
        case 0x0018:
          return 0x18; //Cancel
        case 0x0019:
          return 0x19; //End Of Medium
        case 0x001a:
          return 0x1a; //Substitute
        case 0x001b:
          return 0x1b; //Escape
        case 0x001c:
          return 0x1c; //File Separator
        case 0x001d:
          return 0x1d; //Group Separator
        case 0x001e:
          return 0x1e; //Record Separator
        case 0x001f:
          return 0x1f; //Unit Separator
        case 0x0020:
          return 0x20; //Space
        case 0x0021:
          return 0x21; //Exclamation Mark
        case 0x0022:
          return 0x22; //Quotation Mark
        case 0x0023:
          return 0x23; //Number Sign
        case 0x0024:
          return 0x24; //Dollar Sign
        case 0x0025:
          return 0x25; //Percent Sign
        case 0x0026:
          return 0x26; //Ampersand
        case 0x0027:
          return 0x27; //Apostrophe
        case 0x0028:
          return 0x28; //Left Parenthesis
        case 0x0029:
          return 0x29; //Right Parenthesis
        case 0x002a:
          return 0x2a; //Asterisk
        case 0x002b:
          return 0x2b; //Plus Sign
        case 0x002c:
          return 0x2c; //Comma
        case 0x002d:
          return 0x2d; //Hyphen-Minus
        case 0x002e:
          return 0x2e; //Full Stop
        case 0x002f:
          return 0x2f; //Solidus
        case 0x0030:
          return 0x30; //Digit Zero
        case 0x0031:
          return 0x31; //Digit One
        case 0x0032:
          return 0x32; //Digit Two
        case 0x0033:
          return 0x33; //Digit Three
        case 0x0034:
          return 0x34; //Digit Four
        case 0x0035:
          return 0x35; //Digit Five
        case 0x0036:
          return 0x36; //Digit Six
        case 0x0037:
          return 0x37; //Digit Seven
        case 0x0038:
          return 0x38; //Digit Eight
        case 0x0039:
          return 0x39; //Digit Nine
        case 0x003a:
          return 0x3a; //Colon
        case 0x003b:
          return 0x3b; //Semicolon
        case 0x003c:
          return 0x3c; //Less-Than Sign
        case 0x003d:
          return 0x3d; //Equals Sign
        case 0x003e:
          return 0x3e; //Greater-Than Sign
        case 0x003f:
          return 0x3f; //Question Mark
        case 0x0040:
          return 0x40; //Commercial At
        case 0x0041:
          return 0x41; //Latin Capital Letter A
        case 0x0042:
          return 0x42; //Latin Capital Letter B
        case 0x0043:
          return 0x43; //Latin Capital Letter C
        case 0x0044:
          return 0x44; //Latin Capital Letter D
        case 0x0045:
          return 0x45; //Latin Capital Letter E
        case 0x0046:
          return 0x46; //Latin Capital Letter F
        case 0x0047:
          return 0x47; //Latin Capital Letter G
        case 0x0048:
          return 0x48; //Latin Capital Letter H
        case 0x0049:
          return 0x49; //Latin Capital Letter I
        case 0x004a:
          return 0x4a; //Latin Capital Letter J
        case 0x004b:
          return 0x4b; //Latin Capital Letter K
        case 0x004c:
          return 0x4c; //Latin Capital Letter L
        case 0x004d:
          return 0x4d; //Latin Capital Letter M
        case 0x004e:
          return 0x4e; //Latin Capital Letter N
        case 0x004f:
          return 0x4f; //Latin Capital Letter O
        case 0x0050:
          return 0x50; //Latin Capital Letter P
        case 0x0051:
          return 0x51; //Latin Capital Letter Q
        case 0x0052:
          return 0x52; //Latin Capital Letter R
        case 0x0053:
          return 0x53; //Latin Capital Letter S
        case 0x0054:
          return 0x54; //Latin Capital Letter T
        case 0x0055:
          return 0x55; //Latin Capital Letter U
        case 0x0056:
          return 0x56; //Latin Capital Letter V
        case 0x0057:
          return 0x57; //Latin Capital Letter W
        case 0x0058:
          return 0x58; //Latin Capital Letter X
        case 0x0059:
          return 0x59; //Latin Capital Letter Y
        case 0x005a:
          return 0x5a; //Latin Capital Letter Z
        case 0x005b:
          return 0x5b; //Left Square Bracket
        case 0x005c:
          return 0x5c; //Reverse Solidus
        case 0x005d:
          return 0x5d; //Right Square Bracket
        case 0x005e:
          return 0x5e; //Circumflex Accent
        case 0x005f:
          return 0x5f; //Low Line
        case 0x0060:
          return 0x60; //Grave Accent
        case 0x0061:
          return 0x61; //Latin Small Letter A
        case 0x0062:
          return 0x62; //Latin Small Letter B
        case 0x0063:
          return 0x63; //Latin Small Letter C
        case 0x0064:
          return 0x64; //Latin Small Letter D
        case 0x0065:
          return 0x65; //Latin Small Letter E
        case 0x0066:
          return 0x66; //Latin Small Letter F
        case 0x0067:
          return 0x67; //Latin Small Letter G
        case 0x0068:
          return 0x68; //Latin Small Letter H
        case 0x0069:
          return 0x69; //Latin Small Letter I
        case 0x006a:
          return 0x6a; //Latin Small Letter J
        case 0x006b:
          return 0x6b; //Latin Small Letter K
        case 0x006c:
          return 0x6c; //Latin Small Letter L
        case 0x006d:
          return 0x6d; //Latin Small Letter M
        case 0x006e:
          return 0x6e; //Latin Small Letter N
        case 0x006f:
          return 0x6f; //Latin Small Letter O
        case 0x0070:
          return 0x70; //Latin Small Letter P
        case 0x0071:
          return 0x71; //Latin Small Letter Q
        case 0x0072:
          return 0x72; //Latin Small Letter R
        case 0x0073:
          return 0x73; //Latin Small Letter S
        case 0x0074:
          return 0x74; //Latin Small Letter T
        case 0x0075:
          return 0x75; //Latin Small Letter U
        case 0x0076:
          return 0x76; //Latin Small Letter V
        case 0x0077:
          return 0x77; //Latin Small Letter W
        case 0x0078:
          return 0x78; //Latin Small Letter X
        case 0x0079:
          return 0x79; //Latin Small Letter Y
        case 0x007a:
          return 0x7a; //Latin Small Letter Z
        case 0x007b:
          return 0x7b; //Left Curly Bracket
        case 0x007c:
          return 0x7c; //Vertical Line
        case 0x007d:
          return 0x7d; //Right Curly Bracket
        case 0x007e:
          return 0x7e; //Tilde
        case 0x007f:
          return 0x7f; //Delete
        case 0x0081:
          return 0x81;
        case 0x008d:
          return 0x8d;
        case 0x008f:
          return 0x8f;
        case 0x0090:
          return 0x90;
        case 0x009d:
          return 0x9d;
        case 0x00a0:
          return 0xa0; //No-Break Space
        case 0x00a1:
          return 0xa1; //Inverted Exclamation Mark
        case 0x00a2:
          return 0xa2; //Cent Sign
        case 0x00a3:
          return 0xa3; //Pound Sign
        case 0x00a4:
          return 0xa4; //Currency Sign
        case 0x00a5:
          return 0xa5; //Yen Sign
        case 0x00a6:
          return 0xa6; //Broken Bar
        case 0x00a7:
          return 0xa7; //Section Sign
        case 0x00a8:
          return 0xa8; //Diaeresis
        case 0x00a9:
          return 0xa9; //Copyright Sign
        case 0x00aa:
          return 0xaa; //Feminine Ordinal Indicator
        case 0x00ab:
          return 0xab; //Left-Pointing Double Angle Quotation Mark
        case 0x00ac:
          return 0xac; //Not Sign
        case 0x00ad:
          return 0xad; //Soft Hyphen
        case 0x00ae:
          return 0xae; //Registered Sign
        case 0x00af:
          return 0xaf; //Macron
        case 0x00b0:
          return 0xb0; //Degree Sign
        case 0x00b1:
          return 0xb1; //Plus-Minus Sign
        case 0x00b2:
          return 0xb2; //Superscript Two
        case 0x00b3:
          return 0xb3; //Superscript Three
        case 0x00b4:
          return 0xb4; //Acute Accent
        case 0x00b5:
          return 0xb5; //Micro Sign
        case 0x00b6:
          return 0xb6; //Pilcrow Sign
        case 0x00b7:
          return 0xb7; //Middle Dot
        case 0x00b8:
          return 0xb8; //Cedilla
        case 0x00b9:
          return 0xb9; //Superscript One
        case 0x00ba:
          return 0xba; //Masculine Ordinal Indicator
        case 0x00bb:
          return 0xbb; //Right-Pointing Double Angle Quotation Mark
        case 0x00bc:
          return 0xbc; //Vulgar Fraction One Quarter
        case 0x00bd:
          return 0xbd; //Vulgar Fraction One Half
        case 0x00be:
          return 0xbe; //Vulgar Fraction Three Quarters
        case 0x00bf:
          return 0xbf; //Inverted Question Mark
        case 0x00c0:
          return 0xc0; //Latin Capital Letter A With Grave
        case 0x00c1:
          return 0xc1; //Latin Capital Letter A With Acute
        case 0x00c2:
          return 0xc2; //Latin Capital Letter A With Circumflex
        case 0x00c3:
          return 0xc3; //Latin Capital Letter A With Tilde
        case 0x00c4:
          return 0xc4; //Latin Capital Letter A With Diaeresis
        case 0x00c5:
          return 0xc5; //Latin Capital Letter A With Ring Above
        case 0x00c6:
          return 0xc6; //Latin Capital Ligature Ae
        case 0x00c7:
          return 0xc7; //Latin Capital Letter C With Cedilla
        case 0x00c8:
          return 0xc8; //Latin Capital Letter E With Grave
        case 0x00c9:
          return 0xc9; //Latin Capital Letter E With Acute
        case 0x00ca:
          return 0xca; //Latin Capital Letter E With Circumflex
        case 0x00cb:
          return 0xcb; //Latin Capital Letter E With Diaeresis
        case 0x00cc:
          return 0xcc; //Latin Capital Letter I With Grave
        case 0x00cd:
          return 0xcd; //Latin Capital Letter I With Acute
        case 0x00ce:
          return 0xce; //Latin Capital Letter I With Circumflex
        case 0x00cf:
          return 0xcf; //Latin Capital Letter I With Diaeresis
        case 0x00d0:
          return 0xd0; //Latin Capital Letter Eth
        case 0x00d1:
          return 0xd1; //Latin Capital Letter N With Tilde
        case 0x00d2:
          return 0xd2; //Latin Capital Letter O With Grave
        case 0x00d3:
          return 0xd3; //Latin Capital Letter O With Acute
        case 0x00d4:
          return 0xd4; //Latin Capital Letter O With Circumflex
        case 0x00d5:
          return 0xd5; //Latin Capital Letter O With Tilde
        case 0x00d6:
          return 0xd6; //Latin Capital Letter O With Diaeresis
        case 0x00d7:
          return 0xd7; //Multiplication Sign
        case 0x00d8:
          return 0xd8; //Latin Capital Letter O With Stroke
        case 0x00d9:
          return 0xd9; //Latin Capital Letter U With Grave
        case 0x00da:
          return 0xda; //Latin Capital Letter U With Acute
        case 0x00db:
          return 0xdb; //Latin Capital Letter U With Circumflex
        case 0x00dc:
          return 0xdc; //Latin Capital Letter U With Diaeresis
        case 0x00dd:
          return 0xdd; //Latin Capital Letter Y With Acute
        case 0x00de:
          return 0xde; //Latin Capital Letter Thorn
        case 0x00df:
          return 0xdf; //Latin Small Letter Sharp S
        case 0x00e0:
          return 0xe0; //Latin Small Letter A With Grave
        case 0x00e1:
          return 0xe1; //Latin Small Letter A With Acute
        case 0x00e2:
          return 0xe2; //Latin Small Letter A With Circumflex
        case 0x00e3:
          return 0xe3; //Latin Small Letter A With Tilde
        case 0x00e4:
          return 0xe4; //Latin Small Letter A With Diaeresis
        case 0x00e5:
          return 0xe5; //Latin Small Letter A With Ring Above
        case 0x00e6:
          return 0xe6; //Latin Small Ligature Ae
        case 0x00e7:
          return 0xe7; //Latin Small Letter C With Cedilla
        case 0x00e8:
          return 0xe8; //Latin Small Letter E With Grave
        case 0x00e9:
          return 0xe9; //Latin Small Letter E With Acute
        case 0x00ea:
          return 0xea; //Latin Small Letter E With Circumflex
        case 0x00eb:
          return 0xeb; //Latin Small Letter E With Diaeresis
        case 0x00ec:
          return 0xec; //Latin Small Letter I With Grave
        case 0x00ed:
          return 0xed; //Latin Small Letter I With Acute
        case 0x00ee:
          return 0xee; //Latin Small Letter I With Circumflex
        case 0x00ef:
          return 0xef; //Latin Small Letter I With Diaeresis
        case 0x00f0:
          return 0xf0; //Latin Small Letter Eth
        case 0x00f1:
          return 0xf1; //Latin Small Letter N With Tilde
        case 0x00f2:
          return 0xf2; //Latin Small Letter O With Grave
        case 0x00f3:
          return 0xf3; //Latin Small Letter O With Acute
        case 0x00f4:
          return 0xf4; //Latin Small Letter O With Circumflex
        case 0x00f5:
          return 0xf5; //Latin Small Letter O With Tilde
        case 0x00f6:
          return 0xf6; //Latin Small Letter O With Diaeresis
        case 0x00f7:
          return 0xf7; //Division Sign
        case 0x00f8:
          return 0xf8; //Latin Small Letter O With Stroke
        case 0x00f9:
          return 0xf9; //Latin Small Letter U With Grave
        case 0x00fa:
          return 0xfa; //Latin Small Letter U With Acute
        case 0x00fb:
          return 0xfb; //Latin Small Letter U With Circumflex
        case 0x00fc:
          return 0xfc; //Latin Small Letter U With Diaeresis
        case 0x00fd:
          return 0xfd; //Latin Small Letter Y With Acute
        case 0x00fe:
          return 0xfe; //Latin Small Letter Thorn
        case 0x00ff:
          return 0xff; //Latin Small Letter Y With Diaeresis
        case 0x0100:
          return 0x41; //Latin Capital Letter A With Macron
        case 0x0101:
          return 0x61; //Latin Small Letter A With Macron
        case 0x0102:
          return 0x41; //Latin Capital Letter A With Breve
        case 0x0103:
          return 0x61; //Latin Small Letter A With Breve
        case 0x0104:
          return 0x41; //Latin Capital Letter A With Ogonek
        case 0x0105:
          return 0x61; //Latin Small Letter A With Ogonek
        case 0x0106:
          return 0x43; //Latin Capital Letter C With Acute
        case 0x0107:
          return 0x63; //Latin Small Letter C With Acute
        case 0x0108:
          return 0x43; //Latin Capital Letter C With Circumflex
        case 0x0109:
          return 0x63; //Latin Small Letter C With Circumflex
        case 0x010a:
          return 0x43; //Latin Capital Letter C With Dot Above
        case 0x010b:
          return 0x63; //Latin Small Letter C With Dot Above
        case 0x010c:
          return 0x43; //Latin Capital Letter C With Caron
        case 0x010d:
          return 0x63; //Latin Small Letter C With Caron
        case 0x010e:
          return 0x44; //Latin Capital Letter D With Caron
        case 0x010f:
          return 0x64; //Latin Small Letter D With Caron
        case 0x0110:
          return 0xd0; //Latin Capital Letter D With Stroke
        case 0x0111:
          return 0x64; //Latin Small Letter D With Stroke
        case 0x0112:
          return 0x45; //Latin Capital Letter E With Macron
        case 0x0113:
          return 0x65; //Latin Small Letter E With Macron
        case 0x0114:
          return 0x45; //Latin Capital Letter E With Breve
        case 0x0115:
          return 0x65; //Latin Small Letter E With Breve
        case 0x0116:
          return 0x45; //Latin Capital Letter E With Dot Above
        case 0x0117:
          return 0x65; //Latin Small Letter E With Dot Above
        case 0x0118:
          return 0x45; //Latin Capital Letter E With Ogonek
        case 0x0119:
          return 0x65; //Latin Small Letter E With Ogonek
        case 0x011a:
          return 0x45; //Latin Capital Letter E With Caron
        case 0x011b:
          return 0x65; //Latin Small Letter E With Caron
        case 0x011c:
          return 0x47; //Latin Capital Letter G With Circumflex
        case 0x011d:
          return 0x67; //Latin Small Letter G With Circumflex
        case 0x011e:
          return 0x47; //Latin Capital Letter G With Breve
        case 0x011f:
          return 0x67; //Latin Small Letter G With Breve
        case 0x0120:
          return 0x47; //Latin Capital Letter G With Dot Above
        case 0x0121:
          return 0x67; //Latin Small Letter G With Dot Above
        case 0x0122:
          return 0x47; //Latin Capital Letter G With Cedilla
        case 0x0123:
          return 0x67; //Latin Small Letter G With Cedilla
        case 0x0124:
          return 0x48; //Latin Capital Letter H With Circumflex
        case 0x0125:
          return 0x68; //Latin Small Letter H With Circumflex
        case 0x0126:
          return 0x48; //Latin Capital Letter H With Stroke
        case 0x0127:
          return 0x68; //Latin Small Letter H With Stroke
        case 0x0128:
          return 0x49; //Latin Capital Letter I With Tilde
        case 0x0129:
          return 0x69; //Latin Small Letter I With Tilde
        case 0x012a:
          return 0x49; //Latin Capital Letter I With Macron
        case 0x012b:
          return 0x69; //Latin Small Letter I With Macron
        case 0x012c:
          return 0x49; //Latin Capital Letter I With Breve
        case 0x012d:
          return 0x69; //Latin Small Letter I With Breve
        case 0x012e:
          return 0x49; //Latin Capital Letter I With Ogonek
        case 0x012f:
          return 0x69; //Latin Small Letter I With Ogonek
        case 0x0130:
          return 0x49; //Latin Capital Letter I With Dot Above
        case 0x0131:
          return 0x69; //Latin Small Letter Dotless I
        case 0x0134:
          return 0x4a; //Latin Capital Letter J With Circumflex
        case 0x0135:
          return 0x6a; //Latin Small Letter J With Circumflex
        case 0x0136:
          return 0x4b; //Latin Capital Letter K With Cedilla
        case 0x0137:
          return 0x6b; //Latin Small Letter K With Cedilla
        case 0x0139:
          return 0x4c; //Latin Capital Letter L With Acute
        case 0x013a:
          return 0x6c; //Latin Small Letter L With Acute
        case 0x013b:
          return 0x4c; //Latin Capital Letter L With Cedilla
        case 0x013c:
          return 0x6c; //Latin Small Letter L With Cedilla
        case 0x013d:
          return 0x4c; //Latin Capital Letter L With Caron
        case 0x013e:
          return 0x6c; //Latin Small Letter L With Caron
        case 0x0141:
          return 0x4c; //Latin Capital Letter L With Stroke
        case 0x0142:
          return 0x6c; //Latin Small Letter L With Stroke
        case 0x0143:
          return 0x4e; //Latin Capital Letter N With Acute
        case 0x0144:
          return 0x6e; //Latin Small Letter N With Acute
        case 0x0145:
          return 0x4e; //Latin Capital Letter N With Cedilla
        case 0x0146:
          return 0x6e; //Latin Small Letter N With Cedilla
        case 0x0147:
          return 0x4e; //Latin Capital Letter N With Caron
        case 0x0148:
          return 0x6e; //Latin Small Letter N With Caron
        case 0x014c:
          return 0x4f; //Latin Capital Letter O With Macron
        case 0x014d:
          return 0x6f; //Latin Small Letter O With Macron
        case 0x014e:
          return 0x4f; //Latin Capital Letter O With Breve
        case 0x014f:
          return 0x6f; //Latin Small Letter O With Breve
        case 0x0150:
          return 0x4f; //Latin Capital Letter O With Double Acute
        case 0x0151:
          return 0x6f; //Latin Small Letter O With Double Acute
        case 0x0152:
          return 0x8c; //Latin Capital Ligature Oe
        case 0x0153:
          return 0x9c; //Latin Small Ligature Oe
        case 0x0154:
          return 0x52; //Latin Capital Letter R With Acute
        case 0x0155:
          return 0x72; //Latin Small Letter R With Acute
        case 0x0156:
          return 0x52; //Latin Capital Letter R With Cedilla
        case 0x0157:
          return 0x72; //Latin Small Letter R With Cedilla
        case 0x0158:
          return 0x52; //Latin Capital Letter R With Caron
        case 0x0159:
          return 0x72; //Latin Small Letter R With Caron
        case 0x015a:
          return 0x53; //Latin Capital Letter S With Acute
        case 0x015b:
          return 0x73; //Latin Small Letter S With Acute
        case 0x015c:
          return 0x53; //Latin Capital Letter S With Circumflex
        case 0x015d:
          return 0x73; //Latin Small Letter S With Circumflex
        case 0x015e:
          return 0x53; //Latin Capital Letter S With Cedilla
        case 0x015f:
          return 0x73; //Latin Small Letter S With Cedilla
        case 0x0160:
          return 0x8a; //Latin Capital Letter S With Caron
        case 0x0161:
          return 0x9a; //Latin Small Letter S With Caron
        case 0x0162:
          return 0x54; //Latin Capital Letter T With Cedilla
        case 0x0163:
          return 0x74; //Latin Small Letter T With Cedilla
        case 0x0164:
          return 0x54; //Latin Capital Letter T With Caron
        case 0x0165:
          return 0x74; //Latin Small Letter T With Caron
        case 0x0166:
          return 0x54; //Latin Capital Letter T With Stroke
        case 0x0167:
          return 0x74; //Latin Small Letter T With Stroke
        case 0x0168:
          return 0x55; //Latin Capital Letter U With Tilde
        case 0x0169:
          return 0x75; //Latin Small Letter U With Tilde
        case 0x016a:
          return 0x55; //Latin Capital Letter U With Macron
        case 0x016b:
          return 0x75; //Latin Small Letter U With Macron
        case 0x016c:
          return 0x55; //Latin Capital Letter U With Breve
        case 0x016d:
          return 0x75; //Latin Small Letter U With Breve
        case 0x016e:
          return 0x55; //Latin Capital Letter U With Ring Above
        case 0x016f:
          return 0x75; //Latin Small Letter U With Ring Above
        case 0x0170:
          return 0x55; //Latin Capital Letter U With Double Acute
        case 0x0171:
          return 0x75; //Latin Small Letter U With Double Acute
        case 0x0172:
          return 0x55; //Latin Capital Letter U With Ogonek
        case 0x0173:
          return 0x75; //Latin Small Letter U With Ogonek
        case 0x0174:
          return 0x57; //Latin Capital Letter W With Circumflex
        case 0x0175:
          return 0x77; //Latin Small Letter W With Circumflex
        case 0x0176:
          return 0x59; //Latin Capital Letter Y With Circumflex
        case 0x0177:
          return 0x79; //Latin Small Letter Y With Circumflex
        case 0x0178:
          return 0x9f; //Latin Capital Letter Y With Diaeresis
        case 0x0179:
          return 0x5a; //Latin Capital Letter Z With Acute
        case 0x017a:
          return 0x7a; //Latin Small Letter Z With Acute
        case 0x017b:
          return 0x5a; //Latin Capital Letter Z With Dot Above
        case 0x017c:
          return 0x7a; //Latin Small Letter Z With Dot Above
        case 0x017d:
          return 0x8e; //Latin Capital Letter Z With Caron
        case 0x017e:
          return 0x9e; //Latin Small Letter Z With Caron
        case 0x0180:
          return 0x62; //Latin Small Letter B With Stroke
        case 0x0189:
          return 0xd0; //Latin Capital Letter African D
        case 0x0191:
          return 0x83; //Latin Capital Letter F With Hook
        case 0x0192:
          return 0x83; //Latin Small Letter F With Hook
        case 0x0197:
          return 0x49; //Latin Capital Letter I With Stroke
        case 0x019a:
          return 0x6c; //Latin Small Letter L With Bar
        case 0x019f:
          return 0x4f; //Latin Capital Letter O With Middle Tilde
        case 0x01a0:
          return 0x4f; //Latin Capital Letter O With Horn
        case 0x01a1:
          return 0x6f; //Latin Small Letter O With Horn
        case 0x01ab:
          return 0x74; //Latin Small Letter T With Palatal Hook
        case 0x01ae:
          return 0x54; //Latin Capital Letter T With Retroflex Hook
        case 0x01af:
          return 0x55; //Latin Capital Letter U With Horn
        case 0x01b0:
          return 0x75; //Latin Small Letter U With Horn
        case 0x01b6:
          return 0x7a; //Latin Small Letter Z With Stroke
        case 0x01c0:
          return 0x7c; //Latin Letter Dental Click
        case 0x01c3:
          return 0x21; //Latin Letter Retroflex Click
        case 0x01cd:
          return 0x41; //Latin Capital Letter A With Caron
        case 0x01ce:
          return 0x61; //Latin Small Letter A With Caron
        case 0x01cf:
          return 0x49; //Latin Capital Letter I With Caron
        case 0x01d0:
          return 0x69; //Latin Small Letter I With Caron
        case 0x01d1:
          return 0x4f; //Latin Capital Letter O With Caron
        case 0x01d2:
          return 0x6f; //Latin Small Letter O With Caron
        case 0x01d3:
          return 0x55; //Latin Capital Letter U With Caron
        case 0x01d4:
          return 0x75; //Latin Small Letter U With Caron
        case 0x01d5:
          return 0x55; //Latin Capital Letter U With Diaeresis And Macron
        case 0x01d6:
          return 0x75; //Latin Small Letter U With Diaeresis And Macron
        case 0x01d7:
          return 0x55; //Latin Capital Letter U With Diaeresis And Acute
        case 0x01d8:
          return 0x75; //Latin Small Letter U With Diaeresis And Acute
        case 0x01d9:
          return 0x55; //Latin Capital Letter U With Diaeresis And Caron
        case 0x01da:
          return 0x75; //Latin Small Letter U With Diaeresis And Caron
        case 0x01db:
          return 0x55; //Latin Capital Letter U With Diaeresis And Grave
        case 0x01dc:
          return 0x75; //Latin Small Letter U With Diaeresis And Grave
        case 0x01de:
          return 0x41; //Latin Capital Letter A With Diaeresis And Macron
        case 0x01df:
          return 0x61; //Latin Small Letter A With Diaeresis And Macron
        case 0x01e4:
          return 0x47; //Latin Capital Letter G With Stroke
        case 0x01e5:
          return 0x67; //Latin Small Letter G With Stroke
        case 0x01e6:
          return 0x47; //Latin Capital Letter G With Caron
        case 0x01e7:
          return 0x67; //Latin Small Letter G With Caron
        case 0x01e8:
          return 0x4b; //Latin Capital Letter K With Caron
        case 0x01e9:
          return 0x6b; //Latin Small Letter K With Caron
        case 0x01ea:
          return 0x4f; //Latin Capital Letter O With Ogonek
        case 0x01eb:
          return 0x6f; //Latin Small Letter O With Ogonek
        case 0x01ec:
          return 0x4f; //Latin Capital Letter O With Ogonek And Macron
        case 0x01ed:
          return 0x6f; //Latin Small Letter O With Ogonek And Macron
        case 0x01f0:
          return 0x6a; //Latin Small Letter J With Caron
        case 0x0261:
          return 0x67; //Latin Small Letter Script G
        case 0x02b9:
          return 0x27; //Modifier Letter Prime
        case 0x02ba:
          return 0x22; //Modifier Letter Double Prime
        case 0x02bc:
          return 0x27; //Modifier Letter Apostrophe
        case 0x02c4:
          return 0x5e; //Modifier Letter Up Arrowhead
        case 0x02c6:
          return 0x88; //Modifier Letter Circumflex Accent
        case 0x02c8:
          return 0x27; //Modifier Letter Vertical Line
        case 0x02c9:
          return 0xaf; //Modifier Letter Macron
        case 0x02ca:
          return 0xb4; //Modifier Letter Acute Accent
        case 0x02cb:
          return 0x60; //Modifier Letter Grave Accent
        case 0x02cd:
          return 0x5f; //Modifier Letter Low Macron
        case 0x02da:
          return 0xb0; //Ring Above
        case 0x02dc:
          return 0x98; //Small Tilde
        case 0x0300:
          return 0x60; //Combining Grave Accent
        case 0x0301:
          return 0xb4; //Combining Acute Accent
        case 0x0302:
          return 0x5e; //Combining Circumflex Accent
        case 0x0303:
          return 0x7e; //Combining Tilde
        case 0x0304:
          return 0xaf; //Combining Macron
        case 0x0305:
          return 0xaf; //Combining Overline
        case 0x0308:
          return 0xa8; //Combining Diaeresis
        case 0x030a:
          return 0xb0; //Combining Ring Above
        case 0x030e:
          return 0x22; //Combining Double Vertical Line Above
        case 0x0327:
          return 0xb8; //Combining Cedilla
        case 0x0331:
          return 0x5f; //Combining Macron Below
        case 0x0332:
          return 0x5f; //Combining Low Line
        case 0x037e:
          return 0x3b; //Greek Question Mark
        case 0x0393:
          return 0x47; //Greek Capital Letter Gamma
        case 0x0398:
          return 0x54; //Greek Capital Letter Theta
        case 0x03a3:
          return 0x53; //Greek Capital Letter Sigma
        case 0x03a6:
          return 0x46; //Greek Capital Letter Phi
        case 0x03a9:
          return 0x4f; //Greek Capital Letter Omega
        case 0x03b1:
          return 0x61; //Greek Small Letter Alpha
        case 0x03b2:
          return 0xdf; //Greek Small Letter Beta
        case 0x03b4:
          return 0x64; //Greek Small Letter Delta
        case 0x03b5:
          return 0x65; //Greek Small Letter Epsilon
        case 0x03bc:
          return 0xb5; //Greek Small Letter Mu
        case 0x03c0:
          return 0x70; //Greek Small Letter Pi
        case 0x03c3:
          return 0x73; //Greek Small Letter Sigma
        case 0x03c4:
          return 0x74; //Greek Small Letter Tau
        case 0x03c6:
          return 0x66; //Greek Small Letter Phi
        case 0x04bb:
          return 0x68; //Cyrillic Small Letter Shha
        case 0x0589:
          return 0x3a; //Armenian Full Stop
        case 0x066a:
          return 0x25; //Arabic Percent Sign
        case 0x2000:
          return 0x20; //En Quad
        case 0x2001:
          return 0x20; //Em Quad
        case 0x2002:
          return 0x20; //En Space
        case 0x2003:
          return 0x20; //Em Space
        case 0x2004:
          return 0x20; //Three-Per-Em Space
        case 0x2005:
          return 0x20; //Four-Per-Em Space
        case 0x2006:
          return 0x20; //Six-Per-Em Space
        case 0x2010:
          return 0x2d; //Hyphen
        case 0x2011:
          return 0x2d; //Non-Breaking Hyphen
        case 0x2013:
          return 0x96; //En Dash
        case 0x2014:
          return 0x97; //Em Dash
        case 0x2017:
          return 0x3d; //Double Low Line
        case 0x2018:
          return 0x91; //Left Single Quotation Mark
        case 0x2019:
          return 0x92; //Right Single Quotation Mark
        case 0x201a:
          return 0x82; //Single Low-9 Quotation Mark
        case 0x201c:
          return 0x93; //Left Double Quotation Mark
        case 0x201d:
          return 0x94; //Right Double Quotation Mark
        case 0x201e:
          return 0x84; //Double Low-9 Quotation Mark
        case 0x2020:
          return 0x86; //Dagger
        case 0x2021:
          return 0x87; //Double Dagger
        case 0x2022:
          return 0x95; //Bullet
        case 0x2024:
          return 0xb7; //One Dot Leader
        case 0x2026:
          return 0x85; //Horizontal Ellipsis
        case 0x2030:
          return 0x89; //Per Mille Sign
        case 0x2032:
          return 0x27; //Prime
        case 0x2035:
          return 0x60; //Reversed Prime
        case 0x2039:
          return 0x8b; //Single Left-Pointing Angle Quotation Mark
        case 0x203a:
          return 0x9b; //Single Right-Pointing Angle Quotation Mark
        case 0x2044:
          return 0x2f; //Fraction Slash
        case 0x2070:
          return 0xb0; //Superscript Zero
        case 0x2074:
          return 0x34; //Superscript Four
        case 0x2075:
          return 0x35; //Superscript Five
        case 0x2076:
          return 0x36; //Superscript Six
        case 0x2077:
          return 0x37; //Superscript Seven
        case 0x2078:
          return 0x38; //Superscript Eight
        case 0x207f:
          return 0x6e; //Superscript Latin Small Letter N
        case 0x2080:
          return 0x30; //Subscript Zero
        case 0x2081:
          return 0x31; //Subscript One
        case 0x2082:
          return 0x32; //Subscript Two
        case 0x2083:
          return 0x33; //Subscript Three
        case 0x2084:
          return 0x34; //Subscript Four
        case 0x2085:
          return 0x35; //Subscript Five
        case 0x2086:
          return 0x36; //Subscript Six
        case 0x2087:
          return 0x37; //Subscript Seven
        case 0x2088:
          return 0x38; //Subscript Eight
        case 0x2089:
          return 0x39; //Subscript Nine
        case 0x20ac:
          return 0x80; //Euro Sign
        case 0x20a1:
          return 0xa2; //Colon Sign
        case 0x20a4:
          return 0xa3; //Lira Sign
        case 0x20a7:
          return 0x50; //Peseta Sign
        case 0x2102:
          return 0x43; //Double-Struck Capital C
        case 0x2107:
          return 0x45; //Euler Constant
        case 0x210a:
          return 0x67; //Script Small G
        case 0x210b:
          return 0x48; //Script Capital H
        case 0x210c:
          return 0x48; //Black-Letter Capital H
        case 0x210d:
          return 0x48; //Double-Struck Capital H
        case 0x210e:
          return 0x68; //Planck Constant
        case 0x2110:
          return 0x49; //Script Capital I
        case 0x2111:
          return 0x49; //Black-Letter Capital I
        case 0x2112:
          return 0x4c; //Script Capital L
        case 0x2113:
          return 0x6c; //Script Small L
        case 0x2115:
          return 0x4e; //Double-Struck Capital N
        case 0x2118:
          return 0x50; //Script Capital P
        case 0x2119:
          return 0x50; //Double-Struck Capital P
        case 0x211a:
          return 0x51; //Double-Struck Capital Q
        case 0x211b:
          return 0x52; //Script Capital R
        case 0x211c:
          return 0x52; //Black-Letter Capital R
        case 0x211d:
          return 0x52; //Double-Struck Capital R
        case 0x2122:
          return 0x99; //Trade Mark Sign
        case 0x2124:
          return 0x5a; //Double-Struck Capital Z
        case 0x2128:
          return 0x5a; //Black-Letter Capital Z
        case 0x212a:
          return 0x4b; //Kelvin Sign
        case 0x212b:
          return 0xc5; //Angstrom Sign
        case 0x212c:
          return 0x42; //Script Capital B
        case 0x212d:
          return 0x43; //Black-Letter Capital C
        case 0x212e:
          return 0x65; //Estimated Symbol
        case 0x212f:
          return 0x65; //Script Small E
        case 0x2130:
          return 0x45; //Script Capital E
        case 0x2131:
          return 0x46; //Script Capital F
        case 0x2133:
          return 0x4d; //Script Capital M
        case 0x2134:
          return 0x6f; //Script Small O
        case 0x2205:
          return 0xd8; //Empty Set
        case 0x2212:
          return 0x2d; //Minus Sign
        case 0x2213:
          return 0xb1; //Minus-Or-Plus Sign
        case 0x2215:
          return 0x2f; //Division Slash
        case 0x2216:
          return 0x5c; //Set Minus
        case 0x2217:
          return 0x2a; //Asterisk Operator
        case 0x2218:
          return 0xb0; //Ring Operator
        case 0x2219:
          return 0xb7; //Bullet Operator
        case 0x221a:
          return 0x76; //Square Root
        case 0x221e:
          return 0x38; //Infinity
        case 0x2223:
          return 0x7c; //Divides
        case 0x2229:
          return 0x6e; //Intersection
        case 0x2236:
          return 0x3a; //Ratio
        case 0x223c:
          return 0x7e; //Tilde Operator
        case 0x2248:
          return 0x98; //Almost Equal To
        case 0x2261:
          return 0x3d; //Identical To
        case 0x2264:
          return 0x3d; //Less-Than Or Equal To
        case 0x2265:
          return 0x3d; //Greater-Than Or Equal To
        case 0x226a:
          return 0xab; //Much Less-Than
        case 0x226b:
          return 0xbb; //Much Greater-Than
        case 0x22c5:
          return 0xb7; //Dot Operator
        case 0x2302:
          return 0xa6; //House
        case 0x2303:
          return 0x5e; //Up Arrowhead
        case 0x2310:
          return 0xac; //Reversed Not Sign
        case 0x2320:
          return 0x28; //Top Half Integral
        case 0x2321:
          return 0x29; //Bottom Half Integral
        case 0x2329:
          return 0x3c; //Left-Pointing Angle Bracket
        case 0x232a:
          return 0x3e; //Right-Pointing Angle Bracket
        case 0x2500:
          return 0x2d; //Box Drawings Light Horizontal
        case 0x2502:
          return 0xa6; //Box Drawings Light Vertical
        case 0x250c:
          return 0x2b; //Box Drawings Light Down And Right
        case 0x2510:
          return 0x2b; //Box Drawings Light Down And Left
        case 0x2514:
          return 0x2b; //Box Drawings Light Up And Right
        case 0x2518:
          return 0x2b; //Box Drawings Light Up And Left
        case 0x251c:
          return 0x2b; //Box Drawings Light Vertical And Right
        case 0x2524:
          return 0xa6; //Box Drawings Light Vertical And Left
        case 0x252c:
          return 0x2d; //Box Drawings Light Down And Horizontal
        case 0x2534:
          return 0x2d; //Box Drawings Light Up And Horizontal
        case 0x253c:
          return 0x2b; //Box Drawings Light Vertical And Horizontal
        case 0x2550:
          return 0x2d; //Box Drawings Double Horizontal
        case 0x2551:
          return 0xa6; //Box Drawings Double Vertical
        case 0x2552:
          return 0x2b; //Box Drawings Down Single And Right Double
        case 0x2553:
          return 0x2b; //Box Drawings Down Double And Right Single
        case 0x2554:
          return 0x2b; //Box Drawings Double Down And Right
        case 0x2555:
          return 0x2b; //Box Drawings Down Single And Left Double
        case 0x2556:
          return 0x2b; //Box Drawings Down Double And Left Single
        case 0x2557:
          return 0x2b; //Box Drawings Double Down And Left
        case 0x2558:
          return 0x2b; //Box Drawings Up Single And Right Double
        case 0x2559:
          return 0x2b; //Box Drawings Up Double And Right Single
        case 0x255a:
          return 0x2b; //Box Drawings Double Up And Right
        case 0x255b:
          return 0x2b; //Box Drawings Up Single And Left Double
        case 0x255c:
          return 0x2b; //Box Drawings Up Double And Left Single
        case 0x255d:
          return 0x2b; //Box Drawings Double Up And Left
        case 0x255e:
          return 0xa6; //Box Drawings Vertical Single And Right Double
        case 0x255f:
          return 0xa6; //Box Drawings Vertical Double And Right Single
        case 0x2560:
          return 0xa6; //Box Drawings Double Vertical And Right
        case 0x2561:
          return 0xa6; //Box Drawings Vertical Single And Left Double
        case 0x2562:
          return 0xa6; //Box Drawings Vertical Double And Left Single
        case 0x2563:
          return 0xa6; //Box Drawings Double Vertical And Left
        case 0x2564:
          return 0x2d; //Box Drawings Down Single And Horizontal Double
        case 0x2565:
          return 0x2d; //Box Drawings Down Double And Horizontal Single
        case 0x2566:
          return 0x2d; //Box Drawings Double Down And Horizontal
        case 0x2567:
          return 0x2d; //Box Drawings Up Single And Horizontal Double
        case 0x2568:
          return 0x2d; //Box Drawings Up Double And Horizontal Single
        case 0x2569:
          return 0x2d; //Box Drawings Double Up And Horizontal
        case 0x256a:
          return 0x2b; //Box Drawings Vertical Single And Horizontal Double
        case 0x256b:
          return 0x2b; //Box Drawings Vertical Double And Horizontal Single
        case 0x256c:
          return 0x2b; //Box Drawings Double Vertical And Horizontal
        case 0x2580:
          return 0xaf; //Upper Half Block
        case 0x2584:
          return 0x5f; //Lower Half Block
        case 0x2588:
          return 0xa6; //Full Block
        case 0x258c:
          return 0xa6; //Left Half Block
        case 0x2590:
          return 0xa6; //Right Half Block
        case 0x2591:
          return 0xa6; //Light Shade
        case 0x2592:
          return 0xa6; //Medium Shade
        case 0x2593:
          return 0xa6; //Dark Shade
        case 0x25a0:
          return 0xa6; //Black Square
        case 0x263c:
          return 0xa4; //White Sun With Rays
        case 0x2758:
          return 0x7c; //Light Vertical Bar
        case 0x3000:
          return 0x20; //Ideographic Space
        case 0x3008:
          return 0x3c; //Left Angle Bracket
        case 0x3009:
          return 0x3e; //Right Angle Bracket
        case 0x300a:
          return 0xab; //Left Double Angle Bracket
        case 0x300b:
          return 0xbb; //Right Double Angle Bracket
        case 0x301a:
          return 0x5b; //Left White Square Bracket
        case 0x301b:
          return 0x5d; //Right White Square Bracket
        case 0x30fb:
          return 0xb7; //Katakana Middle Dot
        case 0xff01:
          return 0x21; //Fullwidth Exclamation Mark
        case 0xff02:
          return 0x22; //Fullwidth Quotation Mark
        case 0xff03:
          return 0x23; //Fullwidth Number Sign
        case 0xff04:
          return 0x24; //Fullwidth Dollar Sign
        case 0xff05:
          return 0x25; //Fullwidth Percent Sign
        case 0xff06:
          return 0x26; //Fullwidth Ampersand
        case 0xff07:
          return 0x27; //Fullwidth Apostrophe
        case 0xff08:
          return 0x28; //Fullwidth Left Parenthesis
        case 0xff09:
          return 0x29; //Fullwidth Right Parenthesis
        case 0xff0a:
          return 0x2a; //Fullwidth Asterisk
        case 0xff0b:
          return 0x2b; //Fullwidth Plus Sign
        case 0xff0c:
          return 0x2c; //Fullwidth Comma
        case 0xff0d:
          return 0x2d; //Fullwidth Hyphen-Minus
        case 0xff0e:
          return 0x2e; //Fullwidth Full Stop
        case 0xff0f:
          return 0x2f; //Fullwidth Solidus
        case 0xff10:
          return 0x30; //Fullwidth Digit Zero
        case 0xff11:
          return 0x31; //Fullwidth Digit One
        case 0xff12:
          return 0x32; //Fullwidth Digit Two
        case 0xff13:
          return 0x33; //Fullwidth Digit Three
        case 0xff14:
          return 0x34; //Fullwidth Digit Four
        case 0xff15:
          return 0x35; //Fullwidth Digit Five
        case 0xff16:
          return 0x36; //Fullwidth Digit Six
        case 0xff17:
          return 0x37; //Fullwidth Digit Seven
        case 0xff18:
          return 0x38; //Fullwidth Digit Eight
        case 0xff19:
          return 0x39; //Fullwidth Digit Nine
        case 0xff1a:
          return 0x3a; //Fullwidth Colon
        case 0xff1b:
          return 0x3b; //Fullwidth Semicolon
        case 0xff1c:
          return 0x3c; //Fullwidth Less-Than Sign
        case 0xff1d:
          return 0x3d; //Fullwidth Equals Sign
        case 0xff1e:
          return 0x3e; //Fullwidth Greater-Than Sign
        case 0xff1f:
          return 0x3f; //Fullwidth Question Mark
        case 0xff20:
          return 0x40; //Fullwidth Commercial At
        case 0xff21:
          return 0x41; //Fullwidth Latin Capital Letter A
        case 0xff22:
          return 0x42; //Fullwidth Latin Capital Letter B
        case 0xff23:
          return 0x43; //Fullwidth Latin Capital Letter C
        case 0xff24:
          return 0x44; //Fullwidth Latin Capital Letter D
        case 0xff25:
          return 0x45; //Fullwidth Latin Capital Letter E
        case 0xff26:
          return 0x46; //Fullwidth Latin Capital Letter F
        case 0xff27:
          return 0x47; //Fullwidth Latin Capital Letter G
        case 0xff28:
          return 0x48; //Fullwidth Latin Capital Letter H
        case 0xff29:
          return 0x49; //Fullwidth Latin Capital Letter I
        case 0xff2a:
          return 0x4a; //Fullwidth Latin Capital Letter J
        case 0xff2b:
          return 0x4b; //Fullwidth Latin Capital Letter K
        case 0xff2c:
          return 0x4c; //Fullwidth Latin Capital Letter L
        case 0xff2d:
          return 0x4d; //Fullwidth Latin Capital Letter M
        case 0xff2e:
          return 0x4e; //Fullwidth Latin Capital Letter N
        case 0xff2f:
          return 0x4f; //Fullwidth Latin Capital Letter O
        case 0xff30:
          return 0x50; //Fullwidth Latin Capital Letter P
        case 0xff31:
          return 0x51; //Fullwidth Latin Capital Letter Q
        case 0xff32:
          return 0x52; //Fullwidth Latin Capital Letter R
        case 0xff33:
          return 0x53; //Fullwidth Latin Capital Letter S
        case 0xff34:
          return 0x54; //Fullwidth Latin Capital Letter T
        case 0xff35:
          return 0x55; //Fullwidth Latin Capital Letter U
        case 0xff36:
          return 0x56; //Fullwidth Latin Capital Letter V
        case 0xff37:
          return 0x57; //Fullwidth Latin Capital Letter W
        case 0xff38:
          return 0x58; //Fullwidth Latin Capital Letter X
        case 0xff39:
          return 0x59; //Fullwidth Latin Capital Letter Y
        case 0xff3a:
          return 0x5a; //Fullwidth Latin Capital Letter Z
        case 0xff3b:
          return 0x5b; //Fullwidth Left Square Bracket
        case 0xff3c:
          return 0x5c; //Fullwidth Reverse Solidus
        case 0xff3d:
          return 0x5d; //Fullwidth Right Square Bracket
        case 0xff3e:
          return 0x5e; //Fullwidth Circumflex Accent
        case 0xff3f:
          return 0x5f; //Fullwidth Low Line
        case 0xff40:
          return 0x60; //Fullwidth Grave Accent
        case 0xff41:
          return 0x61; //Fullwidth Latin Small Letter A
        case 0xff42:
          return 0x62; //Fullwidth Latin Small Letter B
        case 0xff43:
          return 0x63; //Fullwidth Latin Small Letter C
        case 0xff44:
          return 0x64; //Fullwidth Latin Small Letter D
        case 0xff45:
          return 0x65; //Fullwidth Latin Small Letter E
        case 0xff46:
          return 0x66; //Fullwidth Latin Small Letter F
        case 0xff47:
          return 0x67; //Fullwidth Latin Small Letter G
        case 0xff48:
          return 0x68; //Fullwidth Latin Small Letter H
        case 0xff49:
          return 0x69; //Fullwidth Latin Small Letter I
        case 0xff4a:
          return 0x6a; //Fullwidth Latin Small Letter J
        case 0xff4b:
          return 0x6b; //Fullwidth Latin Small Letter K
        case 0xff4c:
          return 0x6c; //Fullwidth Latin Small Letter L
        case 0xff4d:
          return 0x6d; //Fullwidth Latin Small Letter M
        case 0xff4e:
          return 0x6e; //Fullwidth Latin Small Letter N
        case 0xff4f:
          return 0x6f; //Fullwidth Latin Small Letter O
        case 0xff50:
          return 0x70; //Fullwidth Latin Small Letter P
        case 0xff51:
          return 0x71; //Fullwidth Latin Small Letter Q
        case 0xff52:
          return 0x72; //Fullwidth Latin Small Letter R
        case 0xff53:
          return 0x73; //Fullwidth Latin Small Letter S
        case 0xff54:
          return 0x74; //Fullwidth Latin Small Letter T
        case 0xff55:
          return 0x75; //Fullwidth Latin Small Letter U
        case 0xff56:
          return 0x76; //Fullwidth Latin Small Letter V
        case 0xff57:
          return 0x77; //Fullwidth Latin Small Letter W
        case 0xff58:
          return 0x78; //Fullwidth Latin Small Letter X
        case 0xff59:
          return 0x79; //Fullwidth Latin Small Letter Y
        case 0xff5a:
          return 0x7a; //Fullwidth Latin Small Letter Z
        case 0xff5b:
          return 0x7b; //Fullwidth Left Curly Bracket
        case 0xff5c:
          return 0x7c; //Fullwidth Vertical Line
        case 0xff5d:
          return 0x7d; //Fullwidth Right Curly Bracket
        case 0xff5e:
          return 0x7e; //Fullwidth Tilde
        default:
          return 0x3f; //Question Mark
      }
    }

    /// <summary>
    /// Gets the assembly title.
    /// </summary>
    /// <value>The assembly title.</value>
    /// <remarks>
    /// from http://www.codekeep.net/snippets/170dc91f-1077-4c7f-ab05-8f82b9d1b682.aspx
    /// </remarks>
    public static string AssemblyTitle
    {
      get
      {
        if (assemblyTitle == null) {
          // Get all Title attributes on this assembly
          object[] attributes = Assembly.GetEntryAssembly()
            .GetCustomAttributes(typeof(AssemblyTitleAttribute), false);
          // If there is at least one Title attribute
          if (attributes.Length > 0) {
            // Select the first one
            AssemblyTitleAttribute titleAttribute =
              (AssemblyTitleAttribute)attributes[0];
            // If it is not an empty string, return it
            if (titleAttribute.Title != "")
              return titleAttribute.Title;
          }
          // If there was no Title attribute, or if the Title attribute was the
          // empty string, return the .exe name
          assemblyTitle = Path.GetFileNameWithoutExtension(
            Assembly.GetExecutingAssembly().CodeBase);
        }
        return assemblyTitle;
      }
    }
  }
}
