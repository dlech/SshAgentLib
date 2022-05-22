// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>


using NUnit.Framework;
using System.IO;

namespace SshAgentLibTests
{
    internal static class Helpers
    {
        /// <summary>
        /// Gets the full path to a file in the "Resources" directory.
        /// </summary>
        /// <param name="directory">
        /// The name of a subdirectory in the "Resources" directory.
        /// </param>
        /// <param name="file">
        /// The name of a file in <paramref name="directory"/>.
        /// </param>
        /// <returns>
        /// The path.
        /// </returns>
        public static string GetResourceFilePath(string directory, string file)
        {
            return Path.GetFullPath(
                Path.Combine(
                    TestContext.CurrentContext.TestDirectory,
                    "..",
                    "..",
                    "Resources",
                    directory,
                    file
                )
            );
        }

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
            return File.OpenRead(GetResourceFilePath(directory, file));
        }

        /// <summary>
        /// Returns a string from the contents of a file.
        /// <summary>
        /// <param name="directory">
        /// The name of a directory in the "Resources" directory.
        /// </param>
        /// <param name="file">
        /// The name of a file in <paramref name="directory"/>.
        /// </param>
        /// <returns>
        /// The string.
        /// </returns>
        public static string ReadStringResourceFile(string directory, string file)
        {
            using (var reader = new StreamReader(OpenResourceFile(directory, file)))
            {
                return reader.ReadLine();
            }
        }
    }
}
