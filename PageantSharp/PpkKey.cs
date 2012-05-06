using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace dlech.PageantSharp
{
	/// <summary>
	/// Class for encapsulating information on encryption keys so that it can be used in PuTTY related programs
	/// </summary>
	public class PpkKey : IDisposable
	{

		public AsymmetricAlgorithm Algorithm
		{
			get;
			set;
		}

		/// <summary>
		/// User comment
		/// </summary>
		public string Comment
		{
			get;
			set;
		}

		~PpkKey() {
			this.Dispose();
		}

		public void Dispose()
		{
			if (this.Algorithm != null) {
				this.Algorithm.Clear();
			}
		}

		/// <summary>
		/// Gets PuTTY formated bytes from public key
		/// </summary>
		/// <param name="Algorithm">AsymmetricAlgorithm to convert. (Currently only supports RSA)</param>
		/// <returns>byte array</returns>
		/// <exception cref="ArgumentException">AsymmetricAlgorithm is not supported</exception>
		public byte[] GetSSH2PublicKeyBlob()
		{

			if (typeof(RSA).IsInstanceOfType(Algorithm)) {

				RSA rsa = (RSA)Algorithm;
				RSAParameters p = rsa.ExportParameters(false);
				PpkKeyBlobBuilder builder = new PpkKeyBlobBuilder();

				builder.AddString(PpkFile.PublicKeyAlgorithms.ssh_rsa);
				builder.AddBigInt(p.Exponent);
				builder.AddBigInt(p.Modulus);

				byte[] result = builder.getBlob();
				builder.Clear();
				return result;
			}

			if (typeof(DSA).IsInstanceOfType(Algorithm)) {

				DSA dsa = (DSA)Algorithm;				
				DSAParameters p = dsa.ExportParameters(false);
				PpkKeyBlobBuilder builder = new PpkKeyBlobBuilder();

				builder.AddString(PpkFile.PublicKeyAlgorithms.ssh_dss);
				builder.AddBigInt(p.P);
				builder.AddBigInt(p.Q);
				builder.AddBigInt(p.G);
				builder.AddBigInt(p.Y);

				byte[] result = builder.getBlob();
				builder.Clear();
				return result;
			}

			throw new ArgumentException(Algorithm.GetType() + " is not supported", "alg");
		}


		/// <summary>
		/// Gets openssh style fingerprint for key.
		/// </summary>
		/// <returns>byte array containing fingerprint data</returns>
		/// <exception cref="System.ArgumentException">If Algorithm is not supported</exception>
		public byte[] GetFingerprint()
		{
			if (typeof(RSA).IsInstanceOfType(Algorithm) || typeof(DSA).IsInstanceOfType(Algorithm)) {					
				using (MD5 md5 = MD5.Create()) {
					return md5.ComputeHash(GetSSH2PublicKeyBlob());
				}
			}			
			throw new ArgumentException(Algorithm.GetType() + " is not supported", "alg");
		}
	}
}
