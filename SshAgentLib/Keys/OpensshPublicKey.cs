// SPDX-License-Identifier: MIT
// Copyright (c) 2017,2022 David Lechner <david@lechnology.com>

using System;
using System.IO;
using System.Linq;
using dlech.SshAgentLib;

namespace SshAgentLib.Keys
{
    public static class OpensshPublicKey
    {
        public static SshPublicKey Read(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            using (var reader = new StreamReader(stream))
            {
                var line = reader.ReadLine().Trim();
                var keyType = new string(line.TakeWhile(c => !char.IsWhiteSpace(c)).ToArray());
                line = line.Substring(keyType.Length).Trim();
                var data = new string(line.TakeWhile(c => !char.IsWhiteSpace(c)).ToArray());
                line = line.Substring(data.Length).Trim();
                var comment = line;

                var algorithm = KeyFormatIdentifier.Parse(keyType);
                var keyData = Convert.FromBase64String(data);

                var key = new SshPublicKey(SshVersion.SSH2, algorithm, keyData, comment);

                return key;
            }
        }
    }
}
