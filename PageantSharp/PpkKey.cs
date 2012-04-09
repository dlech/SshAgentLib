using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace dlech.PageantSharp
{
	public sealed class PpkKey
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
			throw new ArgumentException(Algorithm.GetType() + " is not supported", "alg");
		}


		/// <summary>
		/// Gets openssh style fingerprint for key
		/// </summary>
		/// <returns></returns>
		public byte[] GetFingerprint()
		{
			if (typeof(RSA).IsInstanceOfType(Algorithm)) {					
				using (MD5 md5 = MD5.Create()) {
					return md5.ComputeHash(GetSSH2PublicKeyBlob());
				}
			}
			throw new ArgumentException(Algorithm.GetType() + " is not supported", "alg");
		}
	}
}
