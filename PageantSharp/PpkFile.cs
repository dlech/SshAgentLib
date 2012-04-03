using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Collections.ObjectModel;
using System.Collections;
using System.Security.Cryptography;
using System.Security;

namespace dlech.PageantSharp
{
	/// <summary>
	/// Used to read PuTTY Private Key (.ppk) files
	/// </summary>
	public sealed class PpkFile
	{

		#region -- Constants --

		private const string privKeyDecryptSalt1 = "\0\0\0\0";
		private const string privKeyDecryptSalt2 = "\0\0\0\x1";
		private const string macKeySalt = "putty-private-key-file-mac-key";

		/// <summary>
		/// The delimeter(s) used in the file
		/// </summary>
		private static ReadOnlyCollection<char> delimeters =
			Array.AsReadOnly<char>(new char[] { ':' });

		/// <summary>
		/// contains fields with valid file version strings
		/// </summary>
		public static class FileVersions
		{
			public const string v1 = "1";
			public const string v2 = "2";
		}

		/// <summary>
		/// Collection of supported file versions
		/// </summary>
		public static ReadOnlyCollection<string> supportedFileVersions =
			Array.AsReadOnly<string>(new string[] { FileVersions.v1, FileVersions.v2 });

		/// <summary>
		/// Contains fields with valid pubilc key encryption algorithms
		/// </summary>
		public static class PublicKeyAlgorithms
		{
			public const string ssh_rsa = "ssh-rsa";
			public const string ssh_dss = "ssh-dss";
		}

		/// <summary>
		/// Collection of supported public key encryption algorithms
		/// </summary>
		private static ReadOnlyCollection<string> supportedPublicKeyAlgorithms =
			Array.AsReadOnly<string>(new string[] { PublicKeyAlgorithms.ssh_rsa, PublicKeyAlgorithms.ssh_dss });

		/// <summary>
		/// Contains fields with valid private key encryption algorithms
		/// </summary>
		public static class PrivateKeyAlgorithms
		{
			public const string none = "none";
			public const string aes256_cbc = "aes256-cbc";
		}

		/// <summary>
		/// Collection of supported private key encryption algorithms
		/// </summary>
		private static ReadOnlyCollection<string> supportedPrivateKeyAlgorithms =
			Array.AsReadOnly<string>(new string[] { PrivateKeyAlgorithms.none, PrivateKeyAlgorithms.aes256_cbc });

		/// <summary>
		/// Key that identifies the file version and the public key algorithm
		/// It is the first thing in the file, so it can also be used as a signature
		/// for a quick and dirty file format test.
		/// </summary>
		public const string puttyUserKeyFileKey = "PuTTY-User-Key-File-";

		/// <summary>
		/// Key that indicates the line containing the private key encryption algorithm
		/// </summary>
		private const string privateKeyEncryptionKey = "Encryption";

		/// <summary>
		/// Key that inticates the line containing the user comment
		/// </summary>
		private const string commentKey = "Comment";

		/// <summary>
		/// Key that indicates that the public key follows on the next line 
		/// and the length of the key in lines
		/// </summary>
		private const string publicKeyLinesKey = "Public-Lines";

		/// <summary>
		/// Key that indicates that the private key follows on the next line 
		/// and the length of the key in lines
		/// </summary>
		private const string privateKeyLinesKey = "Private-Lines";

		/// <summary>
		/// Key that indicates that the line contains the hash of the private key (version 2 file format only)
		/// </summary>
		private const string privateMACKey = "Private-MAC";

		/// <summary>
		/// Key that indicates that the line contains the hash of the private key (version 1 file format only)
		/// </summary>
		private const string privateHashKey = "Private-Hash";

		#endregion -- Constants --


		#region -- Properties --

		/// <summary>
		/// File format version (one of FileVersions members)
		/// Callers of this method should warn user 
		/// that version 1 has security issue and should not be used
		/// </summary>
		public string FileVersion { get; private set; }

		/// <summary>
		/// Public key algorithm
		/// One of <see cref="PublicKeyAlgorithms"/>
		/// </summary>
		public string PublicKeyAlgorithm { get; private set; }

		/// <summary>
		/// Private key encryption algorithm
		/// One of <see cref="PrivateKeyAlgorithms"/>
		/// </summary>
		public string PrivateKeyAlgorithm { get; private set; }

		/// <summary>
		/// User comment
		/// </summary>
		public string Comment { get; private set; }

		/// <summary>
		/// The public key
		/// </summary>
		public byte[] PublicKey { get; private set; }

		/// <summary>
		/// The public key as a base64 encoded string
		/// </summary>
		public string PublicKeyString { get; private set; }

		/// <summary>
		/// The private key. Key is encrypted unless <see cref="PrivateKeyAlgorithm"/> is <see cref="PrivateKeyAlgorithms.none"/>.
		/// </summary>
		public byte[] PrivateKey { get; private set; }

		/// <summary>
		/// The private key as a base64 encoded string. Key is encrypted unless <see cref="PrivateKeyAlgorithm"/> is <see cref="PrivateKeyAlgorithms.none"/>.
		/// </summary>
		public string PrivateKeyString { get; private set; }

		/// <summary>
		/// The private key hash
		/// </summary>
		public byte[] PrivateMAC { get; private set; }

		/// <summary>
		/// The private key hash as string of hex digits
		/// </summary>
		public string PrivateMACString { get; private set; }

		/// <summary>
		/// <see cref="PrivateMACString"/> is a MAC as opposed to the old format
		/// </summary>
		public bool IsMAC { get; private set; }

		#endregion -- Properties --


		#region -- Constructors --

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

		#endregion -- Constructors --


		#region -- Public Methods --

		public byte[] DecryptPrivateKey(string passphrase)
		{
			if (passphrase == null) {
				throw new ArgumentNullException("passphrase");
			}

			// only one valid type for now, possibly more in future
			switch (this.PrivateKeyAlgorithm) {

				case PrivateKeyAlgorithms.aes256_cbc:

					/* create key from passphrase */

					SHA1 sha = SHA1.Create();
					sha.Initialize();
					byte[] hash;
					List<byte> key = new List<byte>();
					hash = sha.ComputeHash(Encoding.Default.GetBytes(privKeyDecryptSalt1 + passphrase));
					key.AddRange(hash);
					hash = sha.ComputeHash(Encoding.Default.GetBytes(privKeyDecryptSalt2 + passphrase));
					key.AddRange(hash);
					sha.Clear();

					/* decrypt private key */

					AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
					aes.KeySize = 256;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.None;
					int keySize = aes.KeySize / 8; // convert bits to bytes
					key.RemoveRange(keySize, key.Count - keySize); // remmove extra bytes
					aes.Key = key.ToArray();
					aes.IV = new byte[aes.IV.Length];
					ICryptoTransform decryptor = aes.CreateDecryptor();
					byte[] result = PSUtil.GenericTransform(decryptor, this.PrivateKey);
					aes.Clear();

					/* verify MAC */

					List<byte> macData = new List<byte>();
					if (this.FileVersion != FileVersions.v1) {
						macData.AddRange(PSUtil.IntToBytes(this.PublicKeyAlgorithm.Length));
						macData.AddRange(Encoding.Default.GetBytes(this.PublicKeyAlgorithm));
						macData.AddRange(PSUtil.IntToBytes(this.PrivateKeyAlgorithm.Length));
						macData.AddRange(Encoding.Default.GetBytes(this.PrivateKeyAlgorithm));
						macData.AddRange(PSUtil.IntToBytes(this.Comment.Length));
						macData.AddRange(Encoding.Default.GetBytes(this.Comment));
						macData.AddRange(PSUtil.IntToBytes(this.PublicKey.Length));
						macData.AddRange(this.PublicKey);
						macData.AddRange(PSUtil.IntToBytes(result.Length));
					}
					macData.AddRange(result); // private key					

					byte[] computedHash;
					if (this.IsMAC) {
						HMAC hmac = HMACSHA1.Create();
						sha = SHA1.Create();
						hmac.Key = sha.ComputeHash(Encoding.Default.GetBytes(macKeySalt + passphrase));
						sha.Clear();
						computedHash = hmac.ComputeHash(macData.ToArray());
						hmac.Clear();
					} else {
						sha = SHA1.Create();
						computedHash = sha.ComputeHash(macData.ToArray());
						sha.Clear();
					}
					macData.Clear();

					if (this.PrivateMACString != PSUtil.ToHex(computedHash)) {
						Array.Clear(result, 0, result.Length);
						throw new PpkFileMacException();
					}
					return result;
				default:
					// TODO make a specific exception type???
					throw new Exception("encryption algorithm " + this.PrivateKeyAlgorithm + " not supported");
			}
		}

		public RSAParameters GetRSAParameters()
		{
			return GetRSAParameters(null);
		}

		public RSAParameters GetRSAParameters(string passphrase)
		{			
			KeyParser parser = new KeyParser(this.PublicKey);
			string algorithm = Encoding.Default.GetString(parser.CurrentData);
			parser.MoveNext();

			if ((this.PublicKeyAlgorithm != PublicKeyAlgorithms.ssh_rsa) || 
		  	(algorithm != PublicKeyAlgorithms.ssh_rsa)) {
				throw new InvalidOperationException("key is not rsa");
			}
			
			RSAParameters parameters = new RSAParameters();
			parameters.Exponent = parser.CurrentData;
			parser.MoveNext();
			parameters.Modulus = parser.CurrentData;
			//parser.MoveNext();

			if (passphrase == null) {
				parser = new KeyParser(this.PrivateKey);
			} else {
				parser = new KeyParser(DecryptPrivateKey(passphrase));
			}
			parameters.D = parser.CurrentData;			
			parser.MoveNext();
			parameters.P = parser.CurrentData;
			parser.MoveNext();
			parameters.Q = parser.CurrentData;
			parser.MoveNext();
			parameters.InverseQ = parser.CurrentData;
			//parser.MoveNext();
						
			return parameters;
		}
		#endregion -- Public Methods --


		#region -- Private Methods --

		private void ProcessData(byte[] data)
		{
			string line;
			string[] pair = new string[2];
			int lineCount, i;

			Stream stream = new MemoryStream(data);
			StreamReader reader = new StreamReader(stream);

			line = reader.ReadLine();
			pair = line.Split(delimeters.ToArray(), 2);
			if (!pair[0].StartsWith(puttyUserKeyFileKey)) {
				throw new PpkFileFormatException();
			}
			this.FileVersion = pair[0].Remove(0, puttyUserKeyFileKey.Length);
			if (!supportedFileVersions.Contains(this.FileVersion)) {
				throw new PpkFileFormatException();
			}
			this.PublicKeyAlgorithm = pair[1].Trim();
			if (!supportedPublicKeyAlgorithms.Contains(this.PublicKeyAlgorithm)) {
				throw new PpkFileFormatException();
			}

			line = reader.ReadLine();
			pair = line.Split(delimeters.ToArray(), 2);
			if (pair[0] != privateKeyEncryptionKey) {
				throw new PpkFileFormatException();
			}
			this.PrivateKeyAlgorithm = pair[1].Trim();
			if (!supportedPrivateKeyAlgorithms.Contains(this.PrivateKeyAlgorithm)) {
				throw new PpkFileFormatException();
			}

			line = reader.ReadLine();
			pair = line.Split(delimeters.ToArray(), 2);
			if (pair[0] != commentKey) {
				throw new PpkFileFormatException();
			}
			this.Comment = pair[1].Trim();

			line = reader.ReadLine();
			pair = line.Split(delimeters.ToArray(), 2);
			if (pair[0] != publicKeyLinesKey) {
				throw new PpkFileFormatException();
			}
			if (!int.TryParse(pair[1], out lineCount)) {
				throw new PpkFileFormatException();
			}
			this.PublicKeyString = string.Empty;
			for (i = 0; i < lineCount; i++) {
				this.PublicKeyString += reader.ReadLine();
			}
			this.PublicKey = PSUtil.FromBase64(this.PublicKeyString);

			line = reader.ReadLine();
			pair = line.Split(delimeters.ToArray(), 2);
			if (pair[0] != privateKeyLinesKey) {
				throw new PpkFileFormatException();
			}
			if (!int.TryParse(pair[1], out lineCount)) {
				throw new PpkFileFormatException();
			}
			this.PrivateKeyString = string.Empty;
			for (i = 0; i < lineCount; i++) {
				this.PrivateKeyString += reader.ReadLine();
			}

			this.PrivateKey = PSUtil.FromBase64(this.PrivateKeyString);

			line = reader.ReadLine();
			pair = line.Split(delimeters.ToArray(), 2);
			if (pair[0] != privateMACKey) {
				this.IsMAC = false;
				if (pair[0] != privateHashKey || this.FileVersion != FileVersions.v1) {
					throw new PpkFileFormatException();
				}
			} else {
				this.IsMAC = true;
			}
			this.PrivateMACString = pair[1].Trim();
			this.PrivateMAC = PSUtil.FromHex(this.PrivateMACString);
		}

		# endregion -- Private Methods --
	}
}

