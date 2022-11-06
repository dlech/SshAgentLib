// SPDX-License-Identifier: MIT
// Copyright (c) 2012-2015,2017,2022 David Lechner <david@lechnology.com>
// Author(s): David Lechner
//            Max Laverse

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using SshAgentLib;
using SshAgentLib.Keys;

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

        public override byte[] ReadBytes(int count)
        {
            var bytes = base.ReadBytes(count);

            // ReadBytes may return fewer bytes than we requested.
            // This can lead to an IndexOutOfRange exception in
            // other methods which is considered a critical error
            // and may not be caught by Windows.Forms data bindings.
            if (bytes.Length != count)
            {
                throw new EndOfStreamException();
            }

            return bytes;
        }

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

        OpensshCertificateInfo ReadCertificate()
        {
            var serial = ReadUInt64();
            var type = (OpensshCertType)ReadUInt32();
            var keyId = ReadString();
            var validPrincipals = ReadBlob();
            var validAfter = ReadUInt64();
            var validBefore = ReadUInt64();
            var criticalOptions = ReadBlob();
            var extensions = ReadBlob();
            var reserved = ReadBlob();
            var signatureKeyBlob = ReadBlob();
            var signature = ReadBlob();

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
            var signatureKey = new SshPublicKey(signatureKeyBlob);

            return new OpensshCertificateInfo(
                type,
                serial,
                keyId,
                principalsList,
                validAfterDateTime,
                validBeforeDateTime,
                criticalOptions,
                extensions,
                reserved,
                signatureKey,
                signature
            );
        }

        /// <summary>
        /// reads OpenSSH formatted public key blob and creates
        /// an AsymmetricKeyParameter object
        /// </summary>
        /// <returns>AsymmetricKeyParameter containing the public key</returns>
        public AsymmetricKeyParameter ReadSsh2PublicKeyData(
            out byte[] nonce,
            out OpensshCertificateInfo cert,
            out string application
        )
        {
            nonce = null;
            cert = null;
            application = null;
            var algorithm = KeyFormatIdentifier.Parse(ReadString());

            switch (algorithm)
            {
                case PublicKeyAlgorithm.SshRsa:
                {
                    var n = new BigInteger(1, ReadBlob()); // modulus
                    var e = new BigInteger(1, ReadBlob()); // exponent
                    if (n.BitLength < e.BitLength)
                    {
                        // In some cases, the modulus is first. We can always tell because
                        // it is significantly larger than the exponent.
                        return new RsaKeyParameters(false, e, n);
                    }
                    return new RsaKeyParameters(false, n, e);
                }

                case PublicKeyAlgorithm.SshRsaCertV1:
                {
                    var nonceOrPublicKey = ReadBlob();
                    if (nonceOrPublicKey.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonceOrPublicKey);
                        return certParser.ReadSsh2PublicKeyData(
                            out nonce,
                            out cert,
                            out application
                        );
                    }
                    else
                    {
                        var e = new BigInteger(1, ReadBlob());
                        var n = new BigInteger(1, ReadBlob());

                        nonce = nonceOrPublicKey;
                        cert = ReadCertificate();

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
                    var nonceOrPublicKey = ReadBlob();
                    if (nonceOrPublicKey.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonceOrPublicKey);
                        return certParser.ReadSsh2PublicKeyData(
                            out nonce,
                            out cert,
                            out application
                        );
                    }
                    else
                    {
                        var p = new BigInteger(1, ReadBlob());
                        var q = new BigInteger(1, ReadBlob());
                        var g = new BigInteger(1, ReadBlob());
                        var y = new BigInteger(1, ReadBlob());

                        nonce = nonceOrPublicKey;
                        cert = ReadCertificate();

                        var dsaParams = new DsaParameters(p, q, g);
                        return new DsaPublicKeyParameters(y, dsaParams);
                    }
                }

                case PublicKeyAlgorithm.EcdsaSha2Nistp256:
                case PublicKeyAlgorithm.EcdsaSha2Nistp384:
                case PublicKeyAlgorithm.EcdsaSha2Nistp521:
                case PublicKeyAlgorithm.SkEcdsaSha2Nistp256:
                case PublicKeyAlgorithm.SkEcdsaSha2Nistp384:
                case PublicKeyAlgorithm.SkEcdsaSha2Nistp521:
                {
                    var curveName = ReadString();
                    var publicKey = ReadBlob();

                    if (algorithm.HasApplication())
                    {
                        application = ReadString();
                    }

                    var x9Params = NistNamedCurves.GetByName(curveName.Replace("nistp", "P-"));
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
                case PublicKeyAlgorithm.SkEcdsaSha2Nistp256CertV1:
                case PublicKeyAlgorithm.SkEcdsaSha2Nistp384CertV1:
                case PublicKeyAlgorithm.SkEcdsaSha2Nistp521CertV1:
                {
                    var nonceOrPublicKey = ReadBlob();

                    if (nonceOrPublicKey.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonceOrPublicKey);
                        return certParser.ReadSsh2PublicKeyData(
                            out nonce,
                            out cert,
                            out application
                        );
                    }
                    else
                    {
                        var curveName = ReadString();
                        var publicKey = ReadBlob();

                        if (algorithm.HasApplication())
                        {
                            application = ReadString();
                        }

                        nonce = nonceOrPublicKey;
                        cert = ReadCertificate();

                        var x9Params = NistNamedCurves.GetByName(curveName.Replace("nistp", "P-"));
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
                case PublicKeyAlgorithm.SkSshEd25519:
                {
                    var publicKey = ReadBlob();

                    if (algorithm.HasApplication())
                    {
                        application = ReadString();
                    }

                    return new Ed25519PublicKeyParameters(publicKey);
                }

                case PublicKeyAlgorithm.SshEd25519CertV1:
                case PublicKeyAlgorithm.SkSshEd25519CertV1:
                {
                    var nonceOrPublicKey = ReadBlob();
                    if (nonceOrPublicKey.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonceOrPublicKey);
                        certParser.ReadSsh2PublicKeyData(out nonce, out cert, out application);
                        var publicKey = ReadBlob();

                        return new Ed25519PublicKeyParameters(publicKey);
                    }
                    else
                    {
                        var publicKey = ReadBlob();

                        if (algorithm.HasApplication())
                        {
                            application = ReadString();
                        }

                        nonce = nonceOrPublicKey;
                        cert = ReadCertificate();

                        return new Ed25519PublicKeyParameters(publicKey);
                    }
                }

                case PublicKeyAlgorithm.SshEd448:
                case PublicKeyAlgorithm.SkSshEd448:
                {
                    var publicKey = ReadBlob();

                    if (algorithm.HasApplication())
                    {
                        application = ReadString();
                    }

                    return new Ed448PublicKeyParameters(publicKey);
                }

                case PublicKeyAlgorithm.SshEd448CertV1:
                case PublicKeyAlgorithm.SkSshEd448CertV1:
                {
                    var nonceOrPublicKey = ReadBlob();
                    if (nonceOrPublicKey.Length != 32)
                    {
                        // we are being called from SSH2_AGENTC_ADD_IDENTITY and this blob
                        // is the whole certificate, not the nonce
                        var certParser = new BlobParser(nonceOrPublicKey);
                        certParser.ReadSsh2PublicKeyData(out nonce, out cert, out application);
                        var publicKey = ReadBlob();

                        return new Ed448PublicKeyParameters(publicKey);
                    }
                    else
                    {
                        var publicKey = ReadBlob();

                        if (algorithm.HasApplication())
                        {
                            application = ReadString();
                        }

                        nonce = nonceOrPublicKey;
                        cert = ReadCertificate();

                        return new Ed448PublicKeyParameters(publicKey);
                    }
                }

                default:
                    // unsupported encryption algorithm
                    throw new Exception("Unsupported algorithm");
            }
        }

        /// <summary>
        /// reads private key portion of PuTTY Private Key formatted key blob
        /// </summary>
        /// <returns>the private key</returns>
        /// This is very similar to, but not quite the same as the OpenSSH format.
        /// </remarks>
        public AsymmetricKeyParameter ReadPuttyPrivateKeyData(
            AsymmetricKeyParameter publicKeyParameter
        )
        {
            if (publicKeyParameter is RsaKeyParameters rsaPublicKeyParams)
            {
                var d = new BigInteger(1, ReadBlob());
                var p = new BigInteger(1, ReadBlob());
                var q = new BigInteger(1, ReadBlob());
                var inverseQ = new BigInteger(1, ReadBlob());

                /* compute missing parameters */
                var dp = d.Remainder(p.Subtract(BigInteger.One));
                var dq = d.Remainder(q.Subtract(BigInteger.One));

                var rsaPrivateKeyParams = new RsaPrivateCrtKeyParameters(
                    rsaPublicKeyParams.Modulus,
                    rsaPublicKeyParams.Exponent,
                    d,
                    p,
                    q,
                    dp,
                    dq,
                    inverseQ
                );

                return rsaPrivateKeyParams;
            }

            if (publicKeyParameter is DsaPublicKeyParameters dsaPublicKeyParams)
            {
                var x = new BigInteger(1, ReadBlob());
                var dsaPrivateKeyParams = new DsaPrivateKeyParameters(
                    x,
                    dsaPublicKeyParams.Parameters
                );

                return dsaPrivateKeyParams;
            }

            if (publicKeyParameter is Ed25519PublicKeyParameters)
            {
                var privBlob = ReadBlob();
                var ed25596PrivateKey = new Ed25519PrivateKeyParameters(privBlob);

                return ed25596PrivateKey;
            }

            if (publicKeyParameter is Ed448PublicKeyParameters)
            {
                var privBlob = ReadBlob();
                var ed448PrivateKey = new Ed448PrivateKeyParameters(privBlob);

                return ed448PrivateKey;
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

            throw new NotSupportedException("unsupported encryption algorithm");
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

            if (publicKeyParameter is Ed25519PublicKeyParameters ed25519PublicKeyParameters)
            {
                var ed25519Signature = ReadBlob();
                // the first 32 bytes are the private key, the last 32 bytes
                // are the public key

                if (
                    !ed25519Signature
                        .Skip(32)
                        .SequenceEqual(ed25519PublicKeyParameters.GetEncoded())
                )
                {
                    throw new FormatException("public and private keys to not match");
                }

                var ed25519PrivateKey = new Ed25519PrivateKeyParameters(
                    ed25519Signature.Take(32).ToArray()
                );

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
