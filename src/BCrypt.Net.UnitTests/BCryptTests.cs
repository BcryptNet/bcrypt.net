/*
The MIT License (MIT)
Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
Copyright (c) 2013 Ryan D. Emerle (.Net port)
Copyright (c) 2016/2017 Chris McKee (.Net-core port / patches)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
(the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/


using System.Diagnostics;
using NUnit.Framework;

namespace BCrypt.Net.UnitTests
{
    /// <summary>
    /// BCrypt tests
    /// </summary>
    [TestFixture]
    public class BCryptTests
    {
        readonly string[,] _testVectors = {
			{ "",                                   "$2a$06$DCq7YPn5Rq63x1Lad4cll.",    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." },
			{ "",                                   "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",    "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" },
			{ "",                                   "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",    "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" },
			{ "",                                   "$2a$12$k42ZFHFWqBp3vWli.nIn8u",    "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" },
			{ "a",                                  "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" },
			{ "a",                                  "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",    "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." },
			{ "a",                                  "$2a$10$k87L/MF28Q673VKh8/cPi.",    "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" },
			{ "a",                                  "$2a$12$8NJH3LsPrANStV6XtBakCe",    "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" },
			{ "abc",                                "$2a$06$If6bvum7DFjUnE9p2uDeDu",    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" },
			{ "abc",                                "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",    "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" },
			{ "abc",                                "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",    "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" },
			{ "abc",                                "$2a$12$EXRkfkdmXn2gzds2SSitu.",    "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" },
			{ "abcdefghijklmnopqrstuvwxyz",         "$2a$06$.rCVZVOThsIa97pEDOxvGu",    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" },
			{ "abcdefghijklmnopqrstuvwxyz",         "$2a$08$aTsUwsyowQuzRrDqFflhge",    "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." },
			{ "abcdefghijklmnopqrstuvwxyz",         "$2a$10$fVH8e28OQRj9tqiDXs1e1u",    "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" },
			{ "abcdefghijklmnopqrstuvwxyz",         "$2a$12$D4G5f18o7aMMfwasBL7Gpu",    "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" },
			{ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.",    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" },
			{ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu",    "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" },
			{ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",    "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" },
			{ "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO",    "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },

            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2b$12$WApznUOJfkEGSmYRfnkrPO",    "$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2x$12$WApznUOJfkEGSmYRfnkrPO",    "$2x$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2y$12$WApznUOJfkEGSmYRfnkrPO",    "$2y$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" },
        };

        /**
         * Test method for 'BCrypt.HashPassword(string, string)'
         */
        [Test]
        public void TestHashPassword()
        {
            Trace.Write("BCrypt.HashPassword(): ");
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                string plain = _testVectors[i, 0];
                string salt = _testVectors[i, 1];
                string expected = _testVectors[i, 2];
                string hashed = BCrypt.HashPassword(plain, salt);
                Assert.AreEqual(hashed, expected);
                Trace.Write(".");
            }
            Trace.WriteLine(sw.ElapsedMilliseconds);
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt(int)'
         */
        [Test]
        public void TestGenerateSaltWithWorkFactor()
        {
            Trace.Write("BCrypt.GenerateSalt(log_rounds):");
            for (int i = 4; i <= 10; i++)
            {
                Trace.Write(" " + i + ":");
                for (int j = 0; j < _testVectors.Length / 3; j++)
                {
                    string plain = _testVectors[j, 0];
                    string salt = BCrypt.GenerateSalt(i);
                    string hashed1 = BCrypt.HashPassword(plain, salt);
                    string hashed2 = BCrypt.HashPassword(plain, hashed1);
                    Assert.AreEqual(hashed1, hashed2);
                    Trace.Write(".");
                }
            }
            Trace.WriteLine("");
        }

        [Test, Ignore("This test takes a very long time to run as it uses the max workload")]
        public void TestGenerateSaltWithMaxWorkFactor()
        {
            Trace.Write("BCrypt.GenerateSalt(31):");
            for (int j = 0; j < _testVectors.Length / 3; j++)
            {
                string plain = _testVectors[j, 0];
                string salt = BCrypt.GenerateSalt(31);
                string hashed1 = BCrypt.HashPassword(plain, salt);
                string hashed2 = BCrypt.HashPassword(plain, hashed1);
                Assert.AreEqual(hashed1, hashed2);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt()'
         */
        [Test]
        public void TestGenerateSalt()
        {
            Trace.Write("BCrypt.GenerateSalt():");
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                string plain = _testVectors[i, 0];
                string salt = BCrypt.GenerateSalt();
                string hashed1 = BCrypt.HashPassword(plain, salt);
                string hashed2 = BCrypt.HashPassword(plain, hashed1);
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
            Trace.Write("BCrypt.Verify with good passwords:");
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                string plain = _testVectors[i, 0];
                string expected = _testVectors[i, 2];
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
            Trace.Write("BCrypt.Verify with bad passwords: ");
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                int brokenIndex = (i + 4) % (_testVectors.Length / 3);
                string plain = _testVectors[i, 0];
                string expected = _testVectors[brokenIndex, 2];
                Assert.IsFalse(BCrypt.Verify(plain, expected));
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test for correct hashing of non-US-ASCII passwords
         */
        [Test]
        [TestCase("\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605")]
        [TestCase("ππππππππ")]
        public void TestInternationalChars(string pw1)
        {
            Trace.Write("BCrypt.HashPassword with international chars: ");
            string pw2 = "????????";

            string h1 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt());
            Assert.IsFalse(BCrypt.Verify(pw2, h1));
            Trace.Write(".");

            string h2 = BCrypt.HashPassword(pw2, BCrypt.GenerateSalt());
            Assert.IsFalse(BCrypt.Verify(pw1, h2));
            Trace.Write(".");
            Trace.WriteLine("");
        }


        [Test]
        [TestCase("RwiKnN>9xg3*C)1AZl.)y8f_:GCz,vt3T]PIV)[7kktZZQ)z1HI(gyrqgn6;gyb]eIP>r1f:<xw?R")]
        [TestCase("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>")]
        [TestCase("ππππππππ")]
        [TestCase("ЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя")]
        [TestCase("ÅÍÎÏ˝ÓÔÒÚÆ☃")]
        [TestCase("사회과학원 어학연구소")]
        [TestCase("ﾟ･✿ヾ╲(｡◕‿◕｡)╱✿･ﾟ")]
        [TestCase("👾 🙇 💁 🙅 🙆 🙋 🙎 🙍")]
        public void TestNaughtyStringsHash(string pw1)
        {
            Trace.Write("BCrypt.HashPassword with naughty strings: ");

            string h1 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt());
            Assert.IsTrue(BCrypt.Verify(pw1, h1));

            string h2 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt(), enhancedEntropy:true);
            Assert.IsTrue(BCrypt.Verify(pw1, h2));

            Trace.Write(".");
        }
    }
}
