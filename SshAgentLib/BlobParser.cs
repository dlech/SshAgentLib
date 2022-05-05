// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2015,2017,2022 David Lechner <david@lechnology.com>
// Author(s): David Lechner
//            Max Laverse

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using dlech.SshAgentLib.Crypto;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SshAgentLib;

namespace dlech.SshAgentLib
{
    /// <summary>
    /// used to parse open-ssh blobs
    /// </summary>
    public sealed class BlobParser : BinaryReader
    {
        static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public BlobParser(byte[] blob) : this(new MemoryStream(blob)) { }

        public BlobParser(Stream stream) : base(stream, Encoding.UTF8, leaveOpen: true) { }

        public override short ReadInt16()
        {
            return unchecked((short)ReadUInt16());
        }

        public override ushort ReadUInt16()
        {
            var dataLengthBytes = ReadBytes(sizeof(ushort));
            return (ushort)((dataLengthBytes[0] << 8) | dataLengthBytes[1]);
        }

        public override int ReadInt32()
        {
            return unchecked((int)ReadUInt32());
        }

        public override uint ReadUInt32()
        {
            var dataLengthBytes = ReadBytes(sizeof(uint));
            return (uint)(
                (dataLengthBytes[0] << 24)
                | (dataLengthBytes[1] << 16)
                | (dataLengthBytes[2] << 8)
                | dataLengthBytes[3]
            );
        }

        public override long ReadInt64()
        {
            return unchecked((long)ReadUInt64());
        }

        public override ulong ReadUInt64()
        {
            var dataLengthBytes = ReadBytes(sizeof(ulong));
            return (ulong)(
                (dataLengthBytes[0] << 56)
                | (dataLengthBytes[1] << 48)
                | (dataLengthBytes[2] << 40)
                | (dataLengthBytes[3] << 32)
                | (dataLengthBytes[4] << 24)
                | (dataLengthBytes[5] << 16)
                | (dataLengthBytes[6] << 8)
                | dataLengthBytes[7]
            );
        }

        public Agent.BlobHeader ReadHeader()
        {
            var header = new Agent.BlobHeader
            {
                BlobLength = ReadInt32(),
                Message = (Agent.Message)ReadByte()
            };
            return header;
        }

        public override string ReadString()
        {
            return Encoding.UTF8.GetString(ReadBlob());
        }

        public byte[] ReadBlob()
        {
            return ReadBytes(ReadInt32());
        }

        public byte[] ReadSsh1BigIntBlob()
        {
            var bitCount = ReadUInt16();
            return ReadBits(bitCount);
        }

        public byte[] ReadBits(int bitCount)
        {
            if (bitCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bitCount));
            }

            return ReadBytes((bitCount + 7) / 8);
        }

        OpensshCertificate ReadCertificate(BlobBuilder builder)
        {
            var serial = ReadUInt64();
            builder.AddUInt64(serial);
            var type = (Ssh2CertType)ReadUInt32();
            builder.AddUInt32((uint)type);
            var keyId = ReadString();
            builder.AddStringBlob(keyId);
            var validPrincipals = ReadBlob();
            builder.AddBlob(validPrincipals);
            var validAfter = ReadUInt64();
            builder.AddUInt64(validAfter);
            var validBefore = ReadUInt64();
            builder.AddUInt64(validBefore);
            var criticalOptions = ReadBlob();
            builder.AddBlob(criticalOptions);
            var extensions = ReadBlob();
            builder.AddBlob(extensions);
            var reserved = ReadBlob();
            builder.AddBlob(reserved);
            var signatureKey = ReadBlob();
            builder.AddBlob(signatureKey);
            var signature = ReadBlob();
            builder.AddBlob(signature);

            var principalsParser = new BlobParser(validPrincipals);
            var principalsList = new List<string>();
            while (principalsParser.BaseStream.Position < principalsParser.BaseStream.Length)
            {
                principalsList.Add(principalsParser.ReadString());
            }
            var validAfterDateTime =
                validAfter == ulong.MaxValue ? DateTime.MaxValue : epoch.AddSeconds(validAfter);
            var validBeforeDateTime =
                validBefore == ulong.MaxValue ? DateTime.MaxValue : epoch.AddSeconds(validBefore);
            var signatureKeyParser = new BlobParser(signatureKey);
            var sigKey = signatureKeyParser.ReadSsh2PublicKeyData(out _);

            return new OpensshCertificate(
                builder.GetBlob(),
                type,
                serial,
                keyId,
                principalsList,
                validAfterDateTime,
                validBeforeDateTime,
                criticalOptions,
                extensions,
                sigKey
            );
        }

        /// <summary>
        /// reads OpenSSH formatted public key blob and creates
        /// an AsymmetricKeyParameter object
        /// </summary>
        /// <returns>AsymmetricKeyParameter containing the public key</returns>
        public AsymmetricKeyParameter ReadSsh2PublicKeyData(out OpensshCertificate cert)
        {
            cert = null;
            var algorithm = KeyFormatIdentifier.Parse(ReadString());
            var certBuilder = new BlobBuilder();
            certBuilder.AddStringBlob(algorithm.GetIdentifier());

            switch (algorithm)
            {
                case PublicKeyAlgorithm.SshRsa:
                {
                    var n = new BigInteger(1, ReadBlob()); // modulus
                    var e = new BigInteger(1, ReadBlob()); // exponent
                    if (n.BitLength < e.BitLength)
                    {
                        // In some cases, the modulus is first. We can always tell because
                        // it is significantly larget than the exponent.
                        return new RsaKeyParameters(false, e, n);
                    }
                    return new RsaKeyParameters(false, n, e);
                }

                case PublicKeyAlgorithm.SshRsaCertV1:
                {
                    var nonce = ReadBlob();
                    if (nonce.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonce);
                        return certParser.ReadSsh2PublicKeyData(out cert);
                    }
                    else
                    {
                        certBuilder.AddBlob(nonce);
                        var e = new BigInteger(1, ReadBlob());
                        certBuilder.AddBigIntBlob(e);
                        var n = new BigInteger(1, ReadBlob());
                        certBuilder.AddBigIntBlob(n);

                        cert = ReadCertificate(certBuilder);

                        return new RsaKeyParameters(false, n, e);
                    }
                }

                case PublicKeyAlgorithm.SshDss:
                {
                    var p = new BigInteger(1, ReadBlob());
                    var q = new BigInteger(1, ReadBlob());
                    var g = new BigInteger(1, ReadBlob());
                    var y = new BigInteger(1, ReadBlob());

                    var dsaParams = new DsaParameters(p, q, g);
                    return new DsaPublicKeyParameters(y, dsaParams);
                }

                case PublicKeyAlgorithm.SshDssCertV1:
                {
                    var nonce = ReadBlob();
                    if (nonce.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonce);
                        return certParser.ReadSsh2PublicKeyData(out cert);
                    }
                    else
                    {
                        certBuilder.AddBlob(nonce);
                        var p = new BigInteger(1, ReadBlob());
                        certBuilder.AddBigIntBlob(p);
                        var q = new BigInteger(1, ReadBlob());
                        certBuilder.AddBigIntBlob(q);
                        var g = new BigInteger(1, ReadBlob());
                        certBuilder.AddBigIntBlob(g);
                        var y = new BigInteger(1, ReadBlob());
                        certBuilder.AddBigIntBlob(y);

                        cert = ReadCertificate(certBuilder);

                        var dsaParams = new DsaParameters(p, q, g);
                        return new DsaPublicKeyParameters(y, dsaParams);
                    }
                }

                case PublicKeyAlgorithm.EcdsaSha2Nistp256:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521:
                {
                    var curveName = ReadString();
                    var publicKey = ReadBlob();

                    var x9Params = SecNamedCurves.GetByName(EcCurveToAlgorithm(curveName));
                    var domainParams = new ECDomainParameters(
                        x9Params.Curve,
                        x9Params.G,
                        x9Params.N,
                        x9Params.H
                    );
                    var point = x9Params.Curve.DecodePoint(publicKey);
                    return new ECPublicKeyParameters(point, domainParams);
                }

                case PublicKeyAlgorithm.EcdsaSha2Nistp256CertV1:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384CertV1:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521CertV1:
                {
                    var nonce = ReadBlob();
                    if (nonce.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonce);
                        return certParser.ReadSsh2PublicKeyData(out cert);
                    }
                    else
                    {
                        certBuilder.AddBlob(nonce);
                        var curveName = ReadString();
                        certBuilder.AddStringBlob(curveName);
                        var publicKey = ReadBlob();
                        certBuilder.AddBlob(publicKey);

                        cert = ReadCertificate(certBuilder);

                        var x9Params = SecNamedCurves.GetByName(EcCurveToAlgorithm(curveName));
                        var domainParams = new ECDomainParameters(
                            x9Params.Curve,
                            x9Params.G,
                            x9Params.N,
                            x9Params.H
                        );
                        var point = x9Params.Curve.DecodePoint(publicKey);

                        return new ECPublicKeyParameters(point, domainParams);
                    }
                }

                case PublicKeyAlgorithm.SshEd25519:
                {
                    var publicKey = ReadBlob();
                    return new Ed25519PublicKeyParameter(publicKey);
                }

                case PublicKeyAlgorithm.SshEd25519CertV1:
                {
                    var nonce = ReadBlob();
                    if (nonce.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonce);
                        certParser.ReadSsh2PublicKeyData(out cert);
                        var publicKey = ReadBlob();

                        return new Ed25519PublicKeyParameter(publicKey);
                    }
                    else
                    {
                        certBuilder.AddBlob(nonce);
                        var publicKey = ReadBlob();
                        certBuilder.AddBlob(publicKey);

                        cert = ReadCertificate(certBuilder);

                        return new Ed25519PublicKeyParameter(publicKey);
                    }
                }

                default:
                    // unsupported encryption algorithm
                    throw new Exception("Unsupported algorithm");
            }
        }

        /// <summary>
        /// Convert the Openssh curve name to the BouncyCastle curve name
        /// </summary>
        static string EcCurveToAlgorithm(string name)
        {
            switch (name)
            {
                case "nistp256":
                    return "secp256r1";
                case "nistp384":
                    return "secp384r1";
                case "nistp521":
                    return "secp521r1";
                default:
                    throw new ArgumentException($"Unsupported EC algorithm: {name}", nameof(name));
            }
        }

        /// <summary>
        /// reads private key portion of OpenSSH formatted key blob from stream and
        /// creates a key pair
        /// </summary>
        /// <returns>the private key</returns>
        /// <remarks>
        /// intended to be called immediately after ParseSsh2PublicKeyData
        /// </remarks>
        public AsymmetricKeyParameter ReadSsh2KeyData(AsymmetricKeyParameter publicKeyParameter)
        {
            if (publicKeyParameter is RsaKeyParameters rsaPublicKeyParams)
            {
                var rsaD = new BigInteger(1, ReadBlob());
                var rsaIQMP = new BigInteger(1, ReadBlob());
                var rsaP = new BigInteger(1, ReadBlob());
                var rsaQ = new BigInteger(1, ReadBlob());

                /* compute missing parameters */
                var rsaDP = rsaD.Remainder(rsaP.Subtract(BigInteger.One));
                var rsaDQ = rsaD.Remainder(rsaQ.Subtract(BigInteger.One));

                var rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
                    rsaPublicKeyParams.Modulus,
                    rsaPublicKeyParams.Exponent,
                    rsaD,
                    rsaP,
                    rsaQ,
                    rsaDP,
                    rsaDQ,
                    rsaIQMP
                );

                return rsaPrivateKeyParams;
            }

            if (publicKeyParameter is DsaPublicKeyParameters dsaPublicKeyParams)
            {
                var dsaX = new BigInteger(1, ReadBlob()); // private key

                var dsaPrivateKeyParams = new DsaPrivateKeyParameters(
                    dsaX,
                    dsaPublicKeyParams.Parameters
                );

                return dsaPrivateKeyParams;
            }

            if (publicKeyParameter is ECPublicKeyParameters ecPublicKeyParams)
            {
                var ecdsaPrivate = new BigInteger(1, ReadBlob());

                var ecPrivateKeyParams = new ECPrivateKeyParameters(
                    ecdsaPrivate,
                    ecPublicKeyParams.Parameters
                );

                return ecPrivateKeyParams;
            }

            if (publicKeyParameter is Ed25519PublicKeyParameter)
            {
                var ed25519Signature = ReadBlob();
                var ed25519PrivateKey = new Ed25519PrivateKeyParameter(ed25519Signature);
                return ed25519PrivateKey;
            }

            // unsupported encryption algorithm
            throw new Exception("Unsupported algorithm");
        }

        /// <summary>
        /// reads ssh1 OpenSSH formatted public key blob from stream and creates
        /// an AsymmetricKeyParameter object
        /// </summary>
        /// <param name="Stream">stream to parse</param>
        /// <param name="reverseRsaParameters">
        /// Set to true to read RSA modulus first. Normally exponent is read first.
        /// </param>
        /// <returns>AsymmetricKeyParameter containing the public key</returns>
        public AsymmetricKeyParameter ReadSsh1PublicKeyData(bool reverseRsaParameters = false)
        {
            _ = ReadUInt32(); // key_bits - unused
            var rsaN = new BigInteger(1, ReadSsh1BigIntBlob());
            var rsaE = new BigInteger(1, ReadSsh1BigIntBlob());

            if (reverseRsaParameters)
            {
                return new RsaKeyParameters(false, rsaE, rsaN);
            }
            return new RsaKeyParameters(false, rsaN, rsaE);
        }

        /// <summary>
        /// reads private key portion of OpenSSH ssh1 formatted key blob from stream and
        /// creates a key pair
        /// </summary>
        /// <returns>key pair</returns>
        /// <remarks>
        /// intended to be called immediately after ParseSsh1PublicKeyData
        /// </remarks>
        public AsymmetricCipherKeyPair ReadSsh1KeyData(AsymmetricKeyParameter publicKeyParameter)
        {
            var rsa_d = ReadSsh1BigIntBlob();
            var rsa_iqmp = ReadSsh1BigIntBlob();
            var rsa_q = ReadSsh1BigIntBlob();
            var rsa_p = ReadSsh1BigIntBlob();

            var rsaD = new BigInteger(1, rsa_d);
            var rsaIQMP = new BigInteger(1, rsa_iqmp);
            var rsaP = new BigInteger(1, rsa_p);
            var rsaQ = new BigInteger(1, rsa_q);

            var rsaDP = rsaD.Remainder(rsaP.Subtract(BigInteger.One));
            var rsaDQ = rsaD.Remainder(rsaQ.Subtract(BigInteger.One));

            var rsaPublicKeyParams = publicKeyParameter as RsaKeyParameters;

            var rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
                rsaPublicKeyParams.Modulus,
                rsaPublicKeyParams.Exponent,
                rsaD,
                rsaP,
                rsaQ,
                rsaDP,
                rsaDQ,
                rsaIQMP
            );

            return new AsymmetricCipherKeyPair(rsaPublicKeyParams, rsaPrivateKeyParams);
        }
    }
}
