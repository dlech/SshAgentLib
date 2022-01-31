// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>


using NUnit.Framework;
using System.IO;

namespace SshAgentLibTests
{
    internal static class Helpers
    {
        /// <summary>
        /// Opens a file in the test "Resources" directory for reading.
        /// </summary>
        /// <param name="file">
        /// The name of a file in the "Resources" directory.
        /// </param>
        /// <returns>
        /// The file stream.
        /// </returns>
        public static FileStream OpenResourceFile(string file)
        {
            return OpenResourceFile(".", file);
        }

        /// <summary>
        /// Opens a file in the test "Resources" directory for reading.
        /// </summary>
        /// <param name="directory">
        /// The name of a directory in the "Resources" directory.
        /// </param>
        /// <param name="file">
        /// The name of a file in <paramref name="directory"/>.
        /// </param>
        /// <returns>
        /// The file stream.
        /// </returns>
        public static FileStream OpenResourceFile(string directory, string file)
        {
            return File.OpenRead(
                Path.Combine(
                    TestContext.CurrentContext.TestDirectory,
                    "..",
                    "..",
                    "..",
                    "Resources",
                    directory,
                    file
                )
            );
        }
    }
}
