﻿//
// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
// Copyright (c) 2013 Ryan D. Emerle
// Copyright (c) 2015 David Lechner <david@lechnology.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

using System.Diagnostics;
using NUnit.Framework;
using SshAgentLib.Crypto;

namespace dlech.SshAgentLibTests
{
    /// <summary>
    /// BCrypt tests
    /// </summary>
    [TestFixture]
    public class TestBCrypt
    {
        readonly string[,] _TestVectors =
        {
            {
                "",
                "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
                "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."
            },
            {
                "",
                "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
                "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"
            },
            {
                "",
                "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
                "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"
            },
            {
                "",
                "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
                "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"
            },
            {
                "a",
                "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
                "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"
            },
            {
                "a",
                "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
                "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."
            },
            {
                "a",
                "$2a$10$k87L/MF28Q673VKh8/cPi.",
                "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"
            },
            {
                "a",
                "$2a$12$8NJH3LsPrANStV6XtBakCe",
                "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"
            },
            {
                "abc",
                "$2a$06$If6bvum7DFjUnE9p2uDeDu",
                "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"
            },
            {
                "abc",
                "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
                "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"
            },
            {
                "abc",
                "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
                "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"
            },
            {
                "abc",
                "$2a$12$EXRkfkdmXn2gzds2SSitu.",
                "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"
            },
            {
                "abcdefghijklmnopqrstuvwxyz",
                "$2a$06$.rCVZVOThsIa97pEDOxvGu",
                "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"
            },
            {
                "abcdefghijklmnopqrstuvwxyz",
                "$2a$08$aTsUwsyowQuzRrDqFflhge",
                "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."
            },
            {
                "abcdefghijklmnopqrstuvwxyz",
                "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
                "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"
            },
            {
                "abcdefghijklmnopqrstuvwxyz",
                "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
                "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"
            },
            {
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                "$2a$06$fPIsBO8qRqkjj273rfaOI.",
                "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"
            },
            {
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                "$2a$08$Eq2r4G/76Wv39MzSX262hu",
                "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"
            },
            {
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
                "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"
            },
            {
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
                "$2a$12$WApznUOJfkEGSmYRfnkrPO",
                "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"
            },
        };

        /**
         * Test method for 'BCrypt.HashPassword(string, string)'
         */
        [Test]
        public void TestHashPassword()
        {
            Trace.Write("BCrypt.HashPassword(): ");
            var sw = Stopwatch.StartNew();
            for (var i = 0; i < _TestVectors.Length / 3; i++)
            {
                var plain = _TestVectors[i, 0];
                var salt = _TestVectors[i, 1];
                var expected = _TestVectors[i, 2];
                var hashed = BCrypt.HashPassword(plain, salt);
                Assert.AreEqual(hashed, expected);
                Trace.Write(".");
            }
            Trace.WriteLine(sw.ElapsedMilliseconds);
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt(int)'
         */
        //[Test]
        public void TestGenerateSaltWithWorkFactor()
        {
            Trace.Write("BCrypt.GenerateSalt(log_rounds):");
            for (var i = 4; i <= 12; i++)
            {
                Trace.Write(" " + i + ":");
                for (var j = 0; j < _TestVectors.Length / 3; j++)
                {
                    var plain = _TestVectors[j, 0];
                    var salt = BCrypt.GenerateSalt(i);
                    var hashed1 = BCrypt.HashPassword(plain, salt);
                    var hashed2 = BCrypt.HashPassword(plain, hashed1);
                    Assert.AreEqual(hashed1, hashed2);
                    Trace.Write(".");
                }
            }
            Trace.WriteLine("");
        }

        //[Test]
        public void TestGenerateSaltWithMaxWorkFactor()
        {
            Trace.Write("BCrypt.GenerateSalt(31):");
            for (var j = 0; j < _TestVectors.Length / 3; j++)
            {
                var plain = _TestVectors[j, 0];
                var salt = BCrypt.GenerateSalt(31);
                var hashed1 = BCrypt.HashPassword(plain, salt);
                var hashed2 = BCrypt.HashPassword(plain, hashed1);
                Assert.AreEqual(hashed1, hashed2);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt()'
         */
        //[Test]
        public void TestGenerateSalt()
        {
            Trace.Write("BCrypt.GenerateSalt(): ");
            for (var i = 0; i < _TestVectors.Length / 3; i++)
            {
                var plain = _TestVectors[i, 0];
                var salt = BCrypt.GenerateSalt();
                var hashed1 = BCrypt.HashPassword(plain, salt);
                var hashed2 = BCrypt.HashPassword(plain, hashed1);
                Assert.AreEqual(hashed1, hashed2);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.VerifyPassword(string, string)'
         * expecting success
         */
        [Test]
        public void TestVerifyPasswordSuccess()
        {
            Trace.Write("BCrypt.Verify w/ good passwords: ");
            for (var i = 0; i < _TestVectors.Length / 3; i++)
            {
                var plain = _TestVectors[i, 0];
                var expected = _TestVectors[i, 2];
                Assert.IsTrue(BCrypt.Verify(plain, expected));
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.VerifyPassword(string, string)'
         * expecting failure
         */
        [Test]
        public void TestVerifyPasswordFailure()
        {
            Trace.Write("BCrypt.Verify w/ bad passwords: ");
            for (var i = 0; i < _TestVectors.Length / 3; i++)
            {
                var brokenIndex = (i + 4) % (_TestVectors.Length / 3);
                var plain = _TestVectors[i, 0];
                var expected = _TestVectors[brokenIndex, 2];
                Assert.IsFalse(BCrypt.Verify(plain, expected));
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test for correct hashing of non-US-ASCII passwords
         */
        [Test]
        public void TestInternationalChars()
        {
            Trace.Write("BCrypt.HashPassword w/ international chars: ");
            var pw1 = "ππππππππ";
            var pw2 = "????????";

            var h1 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt());
            Assert.IsFalse(BCrypt.Verify(pw2, h1));
            Trace.Write(".");

            var h2 = BCrypt.HashPassword(pw2, BCrypt.GenerateSalt());
            Assert.IsFalse(BCrypt.Verify(pw1, h2));
            Trace.Write(".");
            Trace.WriteLine("");
        }
    }
}
