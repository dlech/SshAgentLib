using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Collections.ObjectModel;
using System.Collections;
using System.Security.Cryptography;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace dlech.PageantSharp
{
	/// <summary>
	/// Used to read PuTTY Private Key (.ppk) files
	/// </summary>
	public static class PpkFile
	{

		#region -- Constants --

		private const string privKeyDecryptSalt1 = "\0\0\0\0";
		private const string privKeyDecryptSalt2 = "\0\0\0\x1";
		private const string macKeySalt = "putty-private-key-file-mac-key";

		/// <summary>
		/// The delimiter(s) used in the file
		/// </summary>
		private static ReadOnlyCollection<char> delimeters =
			Array.AsReadOnly<char>(new char[] { ':' });

		/// <summary>
		/// contains fields with valid file version strings
		/// </summary>
		private static class FileVersions
		{
			public const string v1 = "1";
			public const string v2 = "2";
		}

		/// <summary>
		/// Collection of supported file versions
		/// </summary>
		private static ReadOnlyCollection<string> supportedFileVersions =
			Array.AsReadOnly<string>(new string[] { FileVersions.v1, FileVersions.v2 });

		/// <summary>
		/// Contains fields with valid public key encryption algorithms
		/// </summary>
		public static class PublicKeyAlgorithms
		{
			public const string ssh_rsa = "ssh-rsa";
			public const string ssh_dss = "ssh-dss";
		}

		/// <summary>
		/// Collection of supported public key encryption algorithms
		/// </summary>
		public static ReadOnlyCollection<string> supportedPublicKeyAlgorithms =
			Array.AsReadOnly<string>(new string[] { PublicKeyAlgorithms.ssh_rsa, PublicKeyAlgorithms.ssh_dss });

		/// <summary>
		/// Contains fields with valid private key encryption algorithms
		/// </summary>
		private static class PrivateKeyAlgorithms
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
		private const string puttyUserKeyFileKey = "PuTTY-User-Key-File-";

		/// <summary>
		/// Key that indicates the line containing the private key encryption algorithm
		/// </summary>
		private const string privateKeyEncryptionKey = "Encryption";

		/// <summary>
		/// Key that indicates the line containing the user comment
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


		#region -- structures --

		private struct FileData
		{

			/// <summary>
			/// File format version (one of FileVersions members)
			/// Callers of this method should warn user 
			/// that version 1 has security issue and should not be used
			/// </summary>
			public string fileVersion;

			/// <summary>
			/// Public key algorithm
			/// One of <see cref="PublicKeyAlgorithms"/>
			/// </summary>
			public string publicKeyAlgorithm;

			/// <summary>
			/// Private key encryption algorithm
			/// One of <see cref="PrivateKeyAlgorithms"/>
			/// </summary>
			public string privateKeyAlgorithm;


			/// <summary>
			/// The public key
			/// </summary>
			public byte[] publicKeyBlob;

			/// <summary>
			/// public key comment
			/// </summary>
			public string comment;

			/// <summary>
			/// The private key.
			/// </summary>
			public PinnedByteArray privateKeyBlob;

			/// <summary>
			/// The private key hash.
			/// </summary>
			public byte[] privateMAC;

			/// <summary>
			/// <see cref="privateMACString"/> is a HMAC as opposed to the old format
			/// </summary>
			public bool isHMAC;

			public SecureString passphrase;

		}

		#endregion -- structures --



		#region -- Delegates --

		/// <summary>
		/// Gets passphrase. This method is only called if the file requires a passphrase.
		/// </summary>
		/// <returns></returns>
		public delegate SecureString GetPassphraseCallback();

		/// <summary>
		/// Implementation of this function shoud warn the user that they are using
		/// an old file format that has know security issues.
		/// </summary>
		public delegate void WarnOldFileFormatCallback();

		#endregion -- Delegates --


		#region -- Constructors --



		#endregion -- Constructors --


		#region -- Public Methods --


		/// <summary>
		/// Reads the specified file, parsed data and creates new PpkKey object from file data
		/// </summary>
		/// <param name="fileName">The name of the file to open</param>
		/// <param name="getPassphrase">Callback method for getting passphrase if required. Can be null if no passphrase.</param>
		/// <param name="warnOldFileFormat">Callback method that warns user that they are using an old file format with known security problems.</param>
		/// <exception cref="dlech.PageantSharp.PpkFileException">there was a problem reading the file</exception>
		/// <exception cref="System.ArgumentNullException">fileName and warnOldFileFormat cannot be null</exception>
		/// <exception cref="System.ArgumentException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.PathTooLongException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.DirectoryNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.UnauthorizedAccessException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.FileNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.NotSupportedException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		public static PpkKey ReadFile(string fileName, GetPassphraseCallback getPassphrase, WarnOldFileFormatCallback warnOldFileFormat)
		{
			FileStream stream;
			byte[] buffer;

			stream = File.OpenRead(fileName);
			try {
				buffer = new byte[stream.Length];
				stream.Read(buffer, 0, buffer.Length);
			} catch {
				throw;
			} finally {
				stream.Close();
			}
			return ParseData(buffer, getPassphrase, warnOldFileFormat);
		}

		/// <summary>
		/// Parses the data from a PuTTY Private Key (.ppk) file.
		/// </summary>
		/// <param name="data">The data to parse.</param>
		/// <param name="getPassphrase">Callback method for getting passphrase if required. Can be null if no passphrase.</param>
		/// <param name="warnOldFileFormat">Callback method that warns user that they are using an old file format with known security problems.</param>
		/// <exception cref="dlech.PageantSharp.PpkFileException">there was a problem parsing the file data</exception>
		/// <exception cref="System.ArgumentNullException">data and warnOldFileFormat cannot be null</exception>
		public static PpkKey ParseData(byte[] data, GetPassphraseCallback getPassphrase, WarnOldFileFormatCallback warnOldFileFormat)
		{
			FileData fileData = new FileData();

			/* check for required parameters */
			if (data == null) {
				throw new ArgumentNullException("data");
			}
			if (warnOldFileFormat == null) {
				throw new ArgumentNullException("warnOldFileFormat");
			}

			string line;
			string[] pair = new string[2];
			int lineCount, i;

			Stream stream = new MemoryStream(data);
			StreamReader reader = new StreamReader(stream);
			char[] delimArray = delimeters.ToArray();

			try {
				/* read file version */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (!pair[0].StartsWith(puttyUserKeyFileKey)) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, puttyUserKeyFileKey + " expected");
				}
				fileData.fileVersion = pair[0].Remove(0, puttyUserKeyFileKey.Length);
				if (!supportedFileVersions.Contains(fileData.fileVersion)) {
					throw new PpkFileException(PpkFileException.ErrorType.FileVersion);
				}
				if (fileData.fileVersion == FileVersions.v1) {
					warnOldFileFormat();
				}

				/* read public key encryption algorithm type */
				fileData.publicKeyAlgorithm = pair[1].Trim();
				if (!supportedPublicKeyAlgorithms.Contains(fileData.publicKeyAlgorithm)) {
					throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
				}

				/* read private key encryption algorithm type */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != privateKeyEncryptionKey) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, privateKeyEncryptionKey + " expected");
				}
				fileData.privateKeyAlgorithm = pair[1].Trim();
				if (!supportedPrivateKeyAlgorithms.Contains(fileData.privateKeyAlgorithm)) {
					throw new PpkFileException(PpkFileException.ErrorType.PrivateKeyEncryption);
				}

				/* read comment */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != commentKey) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, commentKey + " expected");
				}
				fileData.comment = pair[1].Trim();

				/* read public key */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != publicKeyLinesKey) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, publicKeyLinesKey + " expected");
				}
				if (!int.TryParse(pair[1], out lineCount)) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, "integer expected");
				}
				string publicKeyString = string.Empty;
				for (i = 0; i < lineCount; i++) {
					publicKeyString += reader.ReadLine();
				}
				fileData.publicKeyBlob = PSUtil.FromBase64(publicKeyString);

				/* read private key */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != privateKeyLinesKey) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, privateKeyLinesKey + " expected");
				}
				if (!int.TryParse(pair[1], out lineCount)) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, "integer expected");
				}
				string privateKeyString = string.Empty;
				for (i = 0; i < lineCount; i++) {
					privateKeyString += reader.ReadLine();
				}
				fileData.privateKeyBlob = new PinnedByteArray(PSUtil.FromBase64(privateKeyString));

				/* read MAC */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != privateMACKey) {
					fileData.isHMAC = false;
					if (pair[0] != privateHashKey || fileData.fileVersion != FileVersions.v1) {
						throw new PpkFileException(PpkFileException.ErrorType.FileFormat, privateMACKey + " expected");
					}
				} else {
					fileData.isHMAC = true;
				}
				string privateMACString = pair[1].Trim();
				fileData.privateMAC = PSUtil.FromHex(privateMACString);


				/* get passphrase and decrypt private key if required */
				if (fileData.privateKeyAlgorithm != PrivateKeyAlgorithms.none) {
					if (getPassphrase == null) {
						throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
					}
					fileData.passphrase = getPassphrase();
					DecryptPrivateKey(ref fileData);
				}

				VerifyIntegrity(fileData);

				PpkKey key = new PpkKey();
				key.Algorithm = CreateKeyAlgorithm(fileData);
				key.Comment = fileData.comment;
				return key;

			} catch (PpkFileException) {
				throw;
			} catch (Exception ex) {
				throw new PpkFileException(
					PpkFileException.ErrorType.FileFormat,
					"See inner exception.", ex);
			} finally {
				Array.Clear(data, 0, data.Length);
				if (fileData.publicKeyBlob != null) {
					Array.Clear(fileData.publicKeyBlob, 0, fileData.publicKeyBlob.Length);
				}
				if (fileData.privateKeyBlob != null) {
					fileData.privateKeyBlob.Dispose();
				}
				if (fileData.privateMAC != null) {
					Array.Clear(fileData.privateMAC, 0, fileData.privateMAC.Length);
				}
				reader.Close();
				stream.Close();
			}
		}

		#endregion -- Public Methods --


		#region -- Private Methods --



		private static void DecryptPrivateKey(ref FileData fileData)
		{
			switch (fileData.privateKeyAlgorithm) {

				case PrivateKeyAlgorithms.none:
					return;

				case PrivateKeyAlgorithms.aes256_cbc:

					/* create key from passphrase */

					SHA1 sha = SHA1.Create();
					sha.Initialize();
					List<byte> key = new List<byte>();

					using (PinnedByteArray hashData = new PinnedByteArray(privKeyDecryptSalt1.Length + fileData.passphrase.Length)) {
						Array.Copy(Encoding.UTF8.GetBytes(privKeyDecryptSalt1), hashData.Data, privKeyDecryptSalt1.Length);
						IntPtr passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(fileData.passphrase);
						for (int i=0; i < fileData.passphrase.Length; i++) {
							hashData.Data[privKeyDecryptSalt1.Length + i] = Marshal.ReadByte(passphrasePtr, i * 2);
							Marshal.WriteByte(passphrasePtr, i * 2, 0);
						}
						sha.ComputeHash(hashData.Data);
						key.AddRange(sha.Hash);
						Array.Copy(Encoding.UTF8.GetBytes(privKeyDecryptSalt2), hashData.Data, privKeyDecryptSalt2.Length);
						sha.ComputeHash(hashData.Data);
						key.AddRange(sha.Hash);
					}
					sha.Clear();
					/* decrypt private key */

					Aes aes = Aes.Create();
					aes.KeySize = 256;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.None;
					int keySize = aes.KeySize / 8; // convert bits to bytes
					key.RemoveRange(keySize, key.Count - keySize); // remove extra bytes
					aes.Key = key.ToArray();
					PSUtil.ClearByteList(key);
					aes.IV = new byte[aes.IV.Length];
					ICryptoTransform decryptor = aes.CreateDecryptor();
					fileData.privateKeyBlob.Data = PSUtil.GenericTransform(decryptor, fileData.privateKeyBlob.Data);
					decryptor.Dispose();
					aes.Clear();
					break;

				default:
					throw new PpkFileException(PpkFileException.ErrorType.PrivateKeyEncryption);
			}
		}

		private static void VerifyIntegrity(FileData fileData)
		{

			List<byte> macData = new List<byte>();
			if (fileData.fileVersion != FileVersions.v1) {
				macData.AddRange(PSUtil.IntToBytes(fileData.publicKeyAlgorithm.Length));
				macData.AddRange(Encoding.UTF8.GetBytes(fileData.publicKeyAlgorithm));
				macData.AddRange(PSUtil.IntToBytes(fileData.privateKeyAlgorithm.Length));
				macData.AddRange(Encoding.UTF8.GetBytes(fileData.privateKeyAlgorithm));
				macData.AddRange(PSUtil.IntToBytes(fileData.comment.Length));
				macData.AddRange(Encoding.UTF8.GetBytes(fileData.comment));
				macData.AddRange(PSUtil.IntToBytes(fileData.publicKeyBlob.Length));
				macData.AddRange(fileData.publicKeyBlob);
				macData.AddRange(PSUtil.IntToBytes(fileData.privateKeyBlob.Data.Length));
			}
			macData.AddRange(fileData.privateKeyBlob.Data);

			byte[] computedHash;
			SHA1 sha = SHA1.Create();
			if (fileData.isHMAC) {
				HMAC hmac = HMACSHA1.Create();
				if (fileData.passphrase != null) {
					using (PinnedByteArray hashData = new PinnedByteArray(macKeySalt.Length + fileData.passphrase.Length)) {
						Array.Copy(Encoding.UTF8.GetBytes(macKeySalt), hashData.Data, macKeySalt.Length);
						IntPtr passphrasePtr = Marshal.SecureStringToGlobalAllocUnicode(fileData.passphrase);
						for (int i=0; i < fileData.passphrase.Length; i++) {
							hashData.Data[macKeySalt.Length + i] = Marshal.ReadByte(passphrasePtr, i * 2);
							Marshal.WriteByte(passphrasePtr, i * 2, 0);
						}
						hmac.Key = sha.ComputeHash(hashData.Data);
					}
				} else {
					hmac.Key = sha.ComputeHash(Encoding.UTF8.GetBytes(macKeySalt));
				}
				computedHash = hmac.ComputeHash(macData.ToArray());
				hmac.Clear();
			} else {
				computedHash = sha.ComputeHash(macData.ToArray());
			}
			sha.Clear();
			PSUtil.ClearByteList(macData);

			try {
				int macLength = computedHash.Length;
				bool failed = false;
				if (fileData.privateMAC.Length == macLength) {
					for (int i=0; i < macLength; i++) {
						if (fileData.privateMAC[i] != computedHash[i]) {
							failed = true;
							break;
						}
					}
				} else {
					failed = true;
				}
				if (failed) {
					// private key data should start with 3 bytes with value 0 if it was properly
					// decrypted or does not require decryption
					if ((fileData.privateKeyBlob.Data[0] == 0) &&
						(fileData.privateKeyBlob.Data[1] == 0) &&
						(fileData.privateKeyBlob.Data[2] == 0)) {
						// so if they bytes are there, passphrase decrypted properly and something 
						// else is wrong with the file contents
						throw new PpkFileException(PpkFileException.ErrorType.FileCorrupt);
					} else {
						// if the bytes are not zeros, we assume that the data was not properly 
						// decrypted because the passphrase was incorrect. 
						throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
					}
				}
			} catch {
				throw;
			} finally {
				Array.Clear(computedHash, 0, computedHash.Length);
			}
		}

		private static AsymmetricAlgorithm CreateKeyAlgorithm(FileData fileData)
		{
			PpkKeyBlobParser parser;
			string algorithm;
			PinnedByteArray exponent, modulus, d, p, q, inverseQ, dp, dq; // rsa params
			PinnedByteArray /* p, q, */ g, y, x; // dsa params

			switch (fileData.publicKeyAlgorithm) {
				case PublicKeyAlgorithms.ssh_rsa:

					parser = new PpkKeyBlobParser(fileData.publicKeyBlob);
					algorithm = Encoding.UTF8.GetString(parser.CurrentAsPinnedByteArray.Data);
					parser.CurrentAsPinnedByteArray.Dispose();
					parser.MoveNext();

					if ((fileData.publicKeyAlgorithm != PublicKeyAlgorithms.ssh_rsa) ||
						(algorithm != PublicKeyAlgorithms.ssh_rsa)) {
						throw new InvalidOperationException("public key is not rsa");
					}

					/* read parameters that were stored in file */

					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					exponent = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					modulus = parser.CurrentAsPinnedByteArray;
					//parser.MoveNext();

					parser = new PpkKeyBlobParser(fileData.privateKeyBlob.Data);

					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					d = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					p = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					q = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					inverseQ = parser.CurrentAsPinnedByteArray;
					//parser.MoveNext();

					/* compute missing parameters */
					dp = PSUtil.ModMinusOne(d, p);
					dq = PSUtil.ModMinusOne(d, q);

					RSAParameters rsaParams = new RSAParameters();
					rsaParams.Modulus = modulus.Data;
					rsaParams.Exponent = exponent.Data;
					rsaParams.D = d.Data;
					rsaParams.P = p.Data;
					rsaParams.Q = q.Data;
					rsaParams.InverseQ = inverseQ.Data;
					rsaParams.DP = dp.Data;
					rsaParams.DQ = dq.Data;

					RSA rsa = RSA.Create();
					rsa.ImportParameters(rsaParams);

					parser.Dispose();
					modulus.Dispose();
					exponent.Dispose();
					d.Dispose();
					p.Dispose();
					q.Dispose();
					inverseQ.Dispose();
					dp.Dispose();
					dq.Dispose();

					return rsa;
				case PublicKeyAlgorithms.ssh_dss:
					parser = new PpkKeyBlobParser(fileData.publicKeyBlob);
					algorithm = Encoding.UTF8.GetString(parser.CurrentAsPinnedByteArray.Data);
					parser.CurrentAsPinnedByteArray.Dispose();
					parser.MoveNext();

					if ((fileData.publicKeyAlgorithm != PublicKeyAlgorithms.ssh_dss) ||
						(algorithm != PublicKeyAlgorithms.ssh_dss)) {
						throw new InvalidOperationException("public key is not dsa");
					}

					/* read parameters that were stored in file */					

					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					p = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					q = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					g = parser.CurrentAsPinnedByteArray;
					parser.MoveNext();
					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					y = parser.CurrentAsPinnedByteArray;
					//parser.MoveNext();

					parser = new PpkKeyBlobParser(fileData.privateKeyBlob.Data);

					PSUtil.TrimLeadingZero(parser.CurrentAsPinnedByteArray);
					x = parser.CurrentAsPinnedByteArray;					
					//parser.MoveNext();
									
					DSAParameters dsaParams = new DSAParameters();
					dsaParams.P = p.Data;
					dsaParams.Q = q.Data;
					dsaParams.G = g.Data;
					dsaParams.Y = y.Data;
					dsaParams.X = x.Data;

					DSA dsa = DSA.Create();
					dsa.ImportParameters(dsaParams);

					parser.Dispose();
					p.Dispose();
					q.Dispose();
					g.Dispose();
					y.Dispose();
					x.Dispose();

					return dsa;
				default:
					// unsupported encryption algorithm
					throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
			}
		}

		# endregion -- Private Methods --

	}
}

