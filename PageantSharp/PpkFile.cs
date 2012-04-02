using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace dlech.PageantSharp
{
	/// <summary>
	/// Used to read PuTTY Private Key (.ppk) files
	/// </summary>
	public class PpkFile
	{
		private char[] delimeters = { ':' };
		private const string puttyUserKeyFile2Key = "PuTTY-User-Key-File-2";
		private const string encryptionKey = "Encryption";
		private const string commentKey = "Comment";
		private const string publicLinesKey = "Public-Lines";
		private const string privateLinesKey = "Private-Lines";
		private const string privateMACKey = "Private-MAC";

		public string KeyType { get; private set; }
		public string Encryption { get; private set; }
		public string Comment { get; private set; }
		public string PublicKey { get; private set; }
		public string PrivateKey { get; private set; }
		public string PrivateMAC { get; private set; }


		/// <summary>
		/// Creates new instance of PpkFile from data array
		/// </summary>
		/// <param name="data">bytes read from file</param>
		public PpkFile(byte[] data)
		{
			ProcessData(data);
		}

		/// <summary>
		/// Creates new instance of PpkFile from specifed file
		/// </summary>
		/// <param name="fileName">the name of the file to open</param>
		/// <exception cref="System.ArgumentException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.ArgumentNullException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.PathTooLongException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.DirectoryNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.UnauthorizedAccessException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.FileNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.NotSupportedException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		public PpkFile(string fileName)
		{
			FileStream stream = File.OpenRead(fileName);
			byte[] buffer = new byte[stream.Length];
			stream.Read(buffer, 0, buffer.Length);
			ProcessData(buffer);
		}

		private void ProcessData(byte[] data)
		{
			string line;
			string[] pair = new string[2];
			int lineCount, i;

			Stream stream = new MemoryStream(data);
			StreamReader reader = new StreamReader(stream);

			line = reader.ReadLine();
			pair = line.Split(delimeters, 2);
			if (pair[0] != puttyUserKeyFile2Key) {
				throw new PpkFileFormatException();
			}
			this.KeyType = pair[1].Trim();

			line = reader.ReadLine();
			pair = line.Split(delimeters, 2);
			if (pair[0] != encryptionKey) {
				throw new PpkFileFormatException();
			}
			this.Encryption = pair[1].Trim();

			line = reader.ReadLine();
			pair = line.Split(delimeters, 2);
			if (pair[0] != commentKey) {
				throw new PpkFileFormatException();
			}
			this.Comment = pair[1].Trim();

			line = reader.ReadLine();
			pair = line.Split(delimeters, 2);
			if (pair[0] != publicLinesKey) {
				throw new PpkFileFormatException();
			}
			lineCount = int.Parse(pair[1]);
			this.PublicKey = string.Empty;
			for (i = 0; i < lineCount; i++) {
				this.PublicKey += reader.ReadLine();
			}

			line = reader.ReadLine();
			pair = line.Split(delimeters, 2);
			if (pair[0] != privateLinesKey) {
				throw new PpkFileFormatException();
			}
			lineCount = int.Parse(pair[1]);
			this.PrivateKey = string.Empty;
			for (i = 0; i < lineCount; i++) {
				this.PrivateKey += reader.ReadLine();
			}

			line = reader.ReadLine();
			pair = line.Split(delimeters, 2);
			if (pair[0] != privateMACKey) {
				throw new PpkFileFormatException();
			}
			this.PrivateMAC = pair[1].Trim();
		}
	}


}

