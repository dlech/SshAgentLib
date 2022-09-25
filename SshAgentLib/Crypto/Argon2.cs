// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System.Security.Cryptography;

using System;
using System.Runtime.InteropServices;

namespace SshAgentLib.Crypto
{
    internal static class Argon2
    {
        public static class KeyDerivation
        {
            public const string Argon2id = "Argon2id";
            public const string Argon2d = "Argon2d";
            public const string Argon2i = "Argon2i";
        }

        public class Parameters
        {
            internal string Algorithm;
            internal int Memory;
            internal int Passes;
            internal int Parallelism;
            internal byte[] Salt;
        }

        public static DeriveBytes CreateHasher(Parameters parameters, byte[] passphrase)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (passphrase == null)
            {
                throw new ArgumentNullException(nameof(passphrase));
            }

            try
            {
                // try unmanged hasher first for best performance
                return new UnmanagedHasher(parameters, passphrase);
            }
            catch (DllNotFoundException)
            {
                // and fall back to managed implementation if unmanaged libargon2 is not found
                return CreateManagedHasher(parameters, passphrase);
            }
        }

        private class UnmanagedHasher : DeriveBytes
        {
            private readonly HashRaw hashRaw;
            private readonly Parameters parameters;
            private readonly byte[] password;

            public UnmanagedHasher(Parameters parameters, byte[] password)
            {
                // Just using this to throw DllNotFoundException early.
                argon2_type2string(0, 0);

                switch (parameters.Algorithm)
                {
                    case KeyDerivation.Argon2id:
                        hashRaw = argon2id_hash_raw;
                        break;
                    case KeyDerivation.Argon2d:
                        hashRaw = argon2d_hash_raw;
                        break;
                    case KeyDerivation.Argon2i:
                        hashRaw = argon2i_hash_raw;
                        break;
                    default:
                        throw new NotSupportedException("unsupported algorithm");
                }

                this.parameters = parameters;
                this.password = password;
            }

            private delegate int HashRaw(
                uint t_cost,
                uint m_cost,
                uint parallelism,
                byte[] pwd,
                UIntPtr pwdlen,
                byte[] salt,
                UIntPtr saltlen,
                byte[] hash,
                UIntPtr hashlen
            );

            [DllImport("argon2")]
            private static extern IntPtr argon2_type2string(uint type, int uppercase);

            [DllImport("argon2")]
            private static extern int argon2i_hash_raw(
                uint t_cost,
                uint m_cost,
                uint parallelism,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pwd,
                UIntPtr pwdlen,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)] byte[] salt,
                UIntPtr saltlen,
                [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 8)] byte[] hash,
                UIntPtr hashlen
            );

            [DllImport("argon2")]
            private static extern int argon2d_hash_raw(
                uint t_cost,
                uint m_cost,
                uint parallelism,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pwd,
                UIntPtr pwdlen,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)] byte[] salt,
                UIntPtr saltlen,
                [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 8)] byte[] hash,
                UIntPtr hashlen
            );

            [DllImport("argon2")]
            private static extern int argon2id_hash_raw(
                uint t_cost,
                uint m_cost,
                uint parallelism,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pwd,
                UIntPtr pwdlen,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)] byte[] salt,
                UIntPtr saltlen,
                [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 8)] byte[] hash,
                UIntPtr hashlen
            );

            [DllImport("argon2")]
            private static extern IntPtr argon2_error_message(int error_code);

            public override byte[] GetBytes(int cb)
            {
                var hash = new byte[cb];

                var err = hashRaw(
                    (uint)parameters.Passes,
                    (uint)parameters.Memory,
                    (uint)parameters.Parallelism,
                    password,
                    (UIntPtr)password.Length,
                    parameters.Salt,
                    (UIntPtr)parameters.Salt.Length,
                    hash,
                    (UIntPtr)hash.Length
                );

                if (err != 0)
                {
                    var msg = Marshal.PtrToStringAnsi(argon2_error_message(err));
                    throw new CryptographicException(msg);
                }

                return hash;
            }

            public override void Reset()
            {
                throw new NotImplementedException();
            }
        }

#if NO_MANAGED_ARGON2
        // no debian packaged Argon2 implementation is available
        private static DeriveBytes CreateManagedHasher(Parameters parameters, byte[] passphrase)
        {
            throw new NotImplementedException("managed argon2 not implement, install libargon2");
        }
#else
        private static DeriveBytes CreateManagedHasher(Parameters parameters, byte[] passphrase)
        {
            Konscious.Security.Cryptography.Argon2 argon2;

            switch (parameters.Algorithm)
            {
                case KeyDerivation.Argon2id:
                    argon2 = new Konscious.Security.Cryptography.Argon2id(passphrase);
                    break;
                case KeyDerivation.Argon2d:
                    argon2 = new Konscious.Security.Cryptography.Argon2d(passphrase);
                    break;
                case KeyDerivation.Argon2i:
                    argon2 = new Konscious.Security.Cryptography.Argon2i(passphrase);
                    break;
                default:
                    throw new NotSupportedException("unsupported algorithm");
            }

            argon2.MemorySize = parameters.Memory;
            argon2.Iterations = parameters.Passes;
            argon2.DegreeOfParallelism = parameters.Parallelism;
            argon2.Salt = parameters.Salt;

            return argon2;
        }
#endif
    }
}
