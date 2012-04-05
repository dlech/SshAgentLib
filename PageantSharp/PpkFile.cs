using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Collections.ObjectModel;
using System.Collections;
using System.Security.Cryptography;
using System.Security;
using System.Numerics;
using System.Diagnostics;

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


		#region -- global variables --

		/// <summary>
		/// File format version (one of FileVersions members)
		/// Callers of this method should warn user 
		/// that version 1 has security issue and should not be used
		/// </summary>
		private string fileVersion = null;

		/// <summary>
		/// Public key algorithm
		/// One of <see cref="PublicKeyAlgorithms"/>
		/// </summary>
		private string publicKeyAlgorithm = null;

		/// <summary>
		/// Private key encryption algorithm
		/// One of <see cref="PrivateKeyAlgorithms"/>
		/// </summary>
		private string privateKeyAlgorithm = null;

		/// <summary>
		/// User comment
		/// </summary>
		private string comment = null;

		/// <summary>
		/// The public key
		/// </summary>
		private byte[] publicKey = null;

		/// <summary>
		/// The private key.
		/// </summary>
		private byte[] privateKey = null;

		/// <summary>
		/// The private key hash.
		/// </summary>
		private byte[] privateMAC = null;

		/// <summary>
		/// <see cref="privateMACString"/> is a HMAC as opposed to the old format
		/// </summary>
		private bool isHMAC;

		private string passphrase = null;

		#endregion -- global variables --


		#region -- Properties --

		public string Comment
		{
			get { return this.comment; }
		}

		public AsymmetricAlgorithm PublicKeyAlgorithm
		{
			get;
			private set;
		}

		#endregion -- Properties --


		#region -- Delegates --

		/// <summary>
		/// Gets passphrase. This method is only called if the file requires a passphrase.
		/// </summary>
		/// <returns></returns>
		public delegate string GetPassphraseCallback();

		/// <summary>
		/// Implementation of this function shoud warn the user that they are using
		/// an old file format that has know security issues.
		/// </summary>
		public delegate void WarnOldFileFormatCallback();

		#endregion -- Delegates --


		#region -- Constructors --

		/// <summary>
		/// Creates new instance of PpkFile from data array.
		/// data is destroyed.
		/// </summary>
		/// <param name="data">The data to parse. The data is destroyed as soon as it is parsed.</param>
		/// <param name="getPassphrase">Callback method for getting passphrase if required.</param>
		/// <param name="warnOldFileFormat">Callback method that warns user that they are using an old file format with known security problems.</param>
		/// <exception cref="dlech.PageantSharp.PpkFileException">there was a problem reading the file</exception>
		/// <exception cref="System.ArgumentNullException">data and warnOldFileFormat cannot be null</exception>
		public PpkFile(ref byte[] data, GetPassphraseCallback getPassphrase, WarnOldFileFormatCallback warnOldFileFormat)
		{
			ProcessData(ref data, getPassphrase, warnOldFileFormat);
		}

		/// <summary>
		/// Creates new instance of PpkFile from specifed file
		/// </summary>
		/// <param name="fileName">The name of the file to open</param>
		/// <param name="getPassphrase">Callback method for getting passphrase if required.</param>
		/// <param name="warnOldFileFormat">Callback method that warns user that they are using an old file format with known security problems.</param>
		/// <exception cref="dlech.PageantSharp.PpkFileException">there was a problem reading the file</exception>
		/// <exception cref="System.ArgumentNullException">fileName and warnOldFileFormat cannot be null</exception>
		/// <exception cref="System.ArgumentException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.PathTooLongException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.DirectoryNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.UnauthorizedAccessException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.IO.FileNotFoundException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		/// <exception cref="System.NotSupportedException">see <see cref="System.IO.File.OpenRead(string)"/></exception>
		public PpkFile(string fileName, GetPassphraseCallback getPassphrase, WarnOldFileFormatCallback warnOldFileFormat)
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
			ProcessData(ref buffer, getPassphrase, warnOldFileFormat);

		}

		#endregion -- Constructors --


		#region -- Public Methods --



		#endregion -- Public Methods --


		#region -- Private Methods --

		/// <summary>
		/// Parses the data proveded and fills in global variables accordingly.
		/// </summary>
		/// <param name="data">the contents of a valid PuTTY Private Key (.ppk) file</param>
		/// <paparam name="getPassphrase">Callback method to get passphrase</paparam>
		/// <param name="warnOldFileFormat">Callback method to warn user that file is old format</param>
		private void ProcessData(ref byte[] data, GetPassphraseCallback getPassphrase, WarnOldFileFormatCallback warnOldFileFormat)
		{
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
				this.fileVersion = pair[0].Remove(0, puttyUserKeyFileKey.Length);
				if (!supportedFileVersions.Contains(this.fileVersion)) {
					throw new PpkFileException(PpkFileException.ErrorType.FileVersion);
				}
				if (this.fileVersion == FileVersions.v1) {
					warnOldFileFormat();
				}

				/* read public key encryption algorithm type */
				this.publicKeyAlgorithm = pair[1].Trim();
				if (!supportedPublicKeyAlgorithms.Contains(this.publicKeyAlgorithm)) {
					throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
				}

				/* read private key encryption algorithm type */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != privateKeyEncryptionKey) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, privateKeyEncryptionKey + " expected");
				}
				this.privateKeyAlgorithm = pair[1].Trim();
				if (!supportedPrivateKeyAlgorithms.Contains(this.privateKeyAlgorithm)) {
					throw new PpkFileException(PpkFileException.ErrorType.PrivateKeyEncryption);
				}

				/* read comment */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != commentKey) {
					throw new PpkFileException(PpkFileException.ErrorType.FileFormat, commentKey + " expected");
				}
				this.comment = pair[1].Trim();

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
				this.publicKey = PSUtil.FromBase64(publicKeyString);
				// TODO destroy publicKeyString

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
				this.privateKey = PSUtil.FromBase64(privateKeyString);
				// TODO destroy privateKeyString

				/* read MAC */
				line = reader.ReadLine();
				pair = line.Split(delimArray, 2);
				if (pair[0] != privateMACKey) {
					this.isHMAC = false;
					if (pair[0] != privateHashKey || this.fileVersion != FileVersions.v1) {
						throw new PpkFileException(PpkFileException.ErrorType.FileFormat, privateMACKey + " expected");
					}
				} else {
					this.isHMAC = true;
				}
				string privateMACString = pair[1].Trim();
				this.privateMAC = PSUtil.FromHex(privateMACString);


				/* get passphrase and decrypt private key if required */
				if (privateKeyAlgorithm != PrivateKeyAlgorithms.none) {
					if (getPassphrase == null) {
						throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
					}
					this.passphrase = getPassphrase();
					DecryptPrivateKey();
				}

				VerifyIntegrity();
				SetPublicKeyAlgorithm();


			} catch (PpkFileException) {
				throw;
			} catch (Exception ex) {
				throw new PpkFileException(
					PpkFileException.ErrorType.FileFormat,
					"See inner exception.", ex);
			} finally {
				Array.Clear(data, 0, data.Length);
				if (this.publicKey != null) {
					Array.Clear(this.publicKey, 0, this.publicKey.Length);
				}
				if (this.privateKey != null) {
					Array.Clear(this.privateKey, 0, this.privateKey.Length);
				}
				if (this.privateMAC != null) {
					Array.Clear(this.privateMAC, 0, this.privateMAC.Length);
				}
				reader.Close();
				stream.Close();
			}
		}

		private void DecryptPrivateKey()
		{
			switch (this.privateKeyAlgorithm) {

				case PrivateKeyAlgorithms.none:
					return;

				case PrivateKeyAlgorithms.aes256_cbc:

					/* create key from passphrase */

					SHA1 sha = SHA1.Create();
					sha.Initialize();
					byte[] hash;
					List<byte> key = new List<byte>();
					hash = sha.ComputeHash(Encoding.UTF8.GetBytes(privKeyDecryptSalt1 + this.passphrase));
					key.AddRange(hash);
					hash = sha.ComputeHash(Encoding.UTF8.GetBytes(privKeyDecryptSalt2 + this.passphrase));
					key.AddRange(hash);
					Array.Clear(hash, 0, hash.Length);
					sha.Clear();

					/* decrypt private key */

					AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
					aes.KeySize = 256;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.None;
					int keySize = aes.KeySize / 8; // convert bits to bytes
					key.RemoveRange(keySize, key.Count - keySize); // remmove extra bytes
					aes.Key = key.ToArray();
					PSUtil.ClearByteList(ref key);
					aes.IV = new byte[aes.IV.Length];
					ICryptoTransform decryptor = aes.CreateDecryptor();
					PSUtil.GenericTransform(decryptor, ref this.privateKey);
					decryptor.Dispose();
					aes.Clear();

					break;

				default:
					throw new PpkFileException(PpkFileException.ErrorType.PrivateKeyEncryption);
			}
		}

		private void VerifyIntegrity()
		{

			List<byte> macData = new List<byte>();
			if (this.fileVersion != FileVersions.v1) {
				macData.AddRange(PSUtil.IntToBytes(this.publicKeyAlgorithm.Length));
				macData.AddRange(Encoding.UTF8.GetBytes(this.publicKeyAlgorithm));
				macData.AddRange(PSUtil.IntToBytes(this.privateKeyAlgorithm.Length));
				macData.AddRange(Encoding.UTF8.GetBytes(this.privateKeyAlgorithm));
				macData.AddRange(PSUtil.IntToBytes(this.comment.Length));
				macData.AddRange(Encoding.UTF8.GetBytes(this.comment));
				macData.AddRange(PSUtil.IntToBytes(this.publicKey.Length));
				macData.AddRange(this.publicKey);
				macData.AddRange(PSUtil.IntToBytes(this.privateKey.Length));
			}
			macData.AddRange(this.privateKey);

			byte[] computedHash;
			SHA1 sha = SHA1.Create();
			if (this.isHMAC) {
				HMAC hmac = HMACSHA1.Create();
				hmac.Key = sha.ComputeHash(Encoding.UTF8.GetBytes(macKeySalt + this.passphrase));
				computedHash = hmac.ComputeHash(macData.ToArray());
				hmac.Clear();
			} else {
				computedHash = sha.ComputeHash(macData.ToArray());
			}
			sha.Clear();
			PSUtil.ClearByteList(ref macData);

			try {
				int macLength = computedHash.Length;
				if (this.privateMAC.Length != macLength) {
					if (this.passphrase == null) {
						throw new PpkFileException(PpkFileException.ErrorType.FileCorrupt);
					} else {
						throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
					}
				}

				for (int i=0; i < macLength; i++) {
					if (this.privateMAC[i] != computedHash[i]) {
						if (this.passphrase == null) {
							throw new PpkFileException(PpkFileException.ErrorType.FileCorrupt);
						} else {
							throw new PpkFileException(PpkFileException.ErrorType.BadPassphrase);
						}
					}
				}
			} catch {
				throw;
			} finally {
				Array.Clear(computedHash, 0, computedHash.Length);
			}
		}

		private void SetPublicKeyAlgorithm()
		{
			switch (this.publicKeyAlgorithm) {
				case PublicKeyAlgorithms.ssh_rsa:
					
					KeyParser parser = new KeyParser(this.publicKey);
					string algorithm = Encoding.UTF8.GetString(parser.CurrentData);
					parser.MoveNext();

					if ((this.publicKeyAlgorithm != PublicKeyAlgorithms.ssh_rsa) ||
						(algorithm != PublicKeyAlgorithms.ssh_rsa)) {
						throw new InvalidOperationException("public key is not rsa");
					}
					
					/* read parameters that were stored in file */ 

					RSAParameters parameters = new RSAParameters();
					// Skip is to drop leading 0 if it exists
					parameters.Exponent = parser.CurrentData.Skip(parser.CurrentData[0] == 0 ? 1 : 0).ToArray();
					parser.MoveNext();
					parameters.Modulus = parser.CurrentData.Skip(parser.CurrentData[0] == 0 ? 1 : 0).ToArray();
					//parser.MoveNext();

					parser = new KeyParser(this.privateKey);

					parameters.D = parser.CurrentData.Skip(parser.CurrentData[0] == 0 ? 1 : 0).ToArray();
					parser.MoveNext();
					parameters.P = parser.CurrentData.Skip(parser.CurrentData[0] == 0 ? 1 : 0).ToArray();
					parser.MoveNext();
					parameters.Q = parser.CurrentData.Skip(parser.CurrentData[0] == 0 ? 1 : 0).ToArray();
					parser.MoveNext();
					parameters.InverseQ = parser.CurrentData.Skip(parser.CurrentData[0] == 0 ? 1 : 0).ToArray();
					//parser.MoveNext();

					/* compute missing parameters */

					byte[] pad = { 0 }; // needed so BigInteger does not see numbers as negative
					// BigInteger is LittleEndian, parameters are BigEndian
					BigInteger bigD = new BigInteger(parameters.D.Reverse().Concat(pad).ToArray());
					BigInteger bigP = new BigInteger(parameters.P.Reverse().Concat(pad).ToArray());
					BigInteger bigQ = new BigInteger(parameters.Q.Reverse().Concat(pad).ToArray());
					parameters.DP = (bigD % (bigP - BigInteger.One)).ToByteArray().Reverse().ToArray();
					parameters.DP = parameters.DP.Skip(parameters.DP[0] == 0 ? 1 : 0).ToArray();
					parameters.DQ = (bigD % (bigQ - BigInteger.One)).ToByteArray().Reverse().ToArray();
					parameters.DQ = parameters.DQ.Skip(parameters.DQ[0] == 0 ? 1 : 0).ToArray();

					RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();					
					rsa.ImportParameters(parameters);
					this.PublicKeyAlgorithm = rsa;

					break;
				case PublicKeyAlgorithms.ssh_dss:
					throw new NotImplementedException("ssh-dss not implemented yet.");
					break;
				default:
					// unsupported encryption algorithm
					throw new PpkFileException(PpkFileException.ErrorType.PublicKeyEncryption);
			}
		}

		# endregion -- Private Methods --


	}
}

