using System;
using System.Diagnostics;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace BCrypt.Net.Test
{
    /// <summary>
    /// Summary description for UnitTest1
    /// </summary>
    [TestClass]
    public class TestBCrypt
    {
        string[,] test_vectors = {
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
		};

        /**
         * Test method for 'BCrypt.HashPassword(String, String)'
         */
        [TestMethod]
        public void TestHashPassword()
        {
            Trace.Write("BCrypt.hashpw(): ");
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < test_vectors.Length / 3; i++)
            {
                String plain = test_vectors[i, 0];
                String salt = test_vectors[i, 1];
                String expected = test_vectors[i, 2];
                String hashed = BCrypt.HashPassword(plain, salt);
                Assert.AreEqual(hashed, expected);
                Trace.Write(".");
            }
            Trace.WriteLine(sw.ElapsedMilliseconds);
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt(int)'
         */
        [TestMethod]
        public void TestGenerateSaltWithWorkFactor()
        {
            Trace.Write("BCrypt.gensalt(log_rounds):");
            for (int i = 4; i <= 12; i++)
            {
                Trace.Write(" " + i + ":");
                for (int j = 0; j < test_vectors.Length / 3; j++)
                {
                    String plain = test_vectors[j, 0];
                    String salt = BCrypt.GenerateSalt(i);
                    String hashed1 = BCrypt.HashPassword(plain, salt);
                    String hashed2 = BCrypt.HashPassword(plain, hashed1);
                    Assert.AreEqual(hashed1, hashed2);
                    Trace.Write(".");
                }
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt()'
         */
        [TestMethod]
        public void TestGenerateSalt()
        {
            Trace.Write("BCrypt.gensalt(): ");
            for (int i = 0; i < test_vectors.Length / 3; i++)
            {
                String plain = test_vectors[i, 0];
                String salt = BCrypt.GenerateSalt();
                String hashed1 = BCrypt.HashPassword(plain, salt);
                String hashed2 = BCrypt.HashPassword(plain, hashed1);
                Assert.AreEqual(hashed1, hashed2);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.VerifyPassword(String, String)'
         * expecting success
         */
        [TestMethod]
        public void TestVerifyPasswordSuccess()
        {
            Trace.Write("BCrypt.checkpw w/ good passwords: ");
            for (int i = 0; i < test_vectors.Length / 3; i++)
            {
                String plain = test_vectors[i, 0];
                String expected = test_vectors[i, 2];
                Assert.IsTrue(BCrypt.VerifyPassword(plain, expected));
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.VerifyPassword(String, String)'
         * expecting failure
         */
        [TestMethod]
        public void TestVerifyPasswordFailure()
        {
            Trace.Write("BCrypt.checkpw w/ bad passwords: ");
            for (int i = 0; i < test_vectors.Length / 3; i++)
            {
                int broken_index = (i + 4) % (test_vectors.Length / 3);
                String plain = test_vectors[i, 0];
                String expected = test_vectors[broken_index, 2];
                Assert.IsFalse(BCrypt.VerifyPassword(plain, expected));
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test for correct hashing of non-US-ASCII passwords
         */
        [TestMethod]
        public void TestInternationalChars()
        {
            Trace.Write("BCrypt.hashpw w/ international chars: ");
            String pw1 = "ππππππππ";
            String pw2 = "????????";

            String h1 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt());
            Assert.IsFalse(BCrypt.VerifyPassword(pw2, h1));
            Trace.Write(".");

            String h2 = BCrypt.HashPassword(pw2, BCrypt.GenerateSalt());
            Assert.IsFalse(BCrypt.VerifyPassword(pw1, h2));
            Trace.Write(".");
            Trace.WriteLine("");
        }
    }
}
