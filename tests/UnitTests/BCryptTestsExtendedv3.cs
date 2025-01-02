/*
The MIT License (MIT)
Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
Copyright (c) 2013 Ryan D. Emerle (.Net port)
Copyright (c) 2016/2025 Chris McKee (.Net-core port / patches / new features)

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

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace BCryptNet.UnitTests
{
#if NET8_0_OR_GREATER

    /// <summary>
    /// BCrypt tests
    /// </summary>
    public class BCryptTestsExtendedV3
    {
        private static readonly Encoding SafeUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private static readonly string HMACKey = Guid.NewGuid().ToString();

        private readonly string[,] _testVectors = new[,] {
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

        /// <summary>
        /// Hashes created using other languages
        /// </summary>
        private readonly string[,] _otherLibTestVectors = new[,] {
            //passlib in python prehashed using SHA256; 7 rounds on bcrypt
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2b$07$9IpAgJw99HWJur2uj3vr3O",    "$2b$07$9IpAgJw99HWJur2uj3vr3OyXMLQ05R2dQE.L5iGnbcVFgMRpsPZRG" },
            { "",                                   "$2b$07$0AD340gChkx46nsejmoRw.",    "$2b$07$0AD340gChkx46nsejmoRw.ANNVeZY33cuGluoj/QhaGEFNGb3sg8O" },
            { "a",                                  "$2b$07$uCq3i6F42wcUHItGwO84jO",    "$2b$07$uCq3i6F42wcUHItGwO84jObhWccJLbVf9vUyXMo0NEW8MkhQHuoS." },
            { "abcdefghijklmnopqrstuvwxyz",         "$2b$07$IZIyfWJFuytjdR41r/Fm7.",    "$2b$07$IZIyfWJFuytjdR41r/Fm7.AeV62vhwnzULJwzXuEdtgUMADnq97fu" },
            { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2b$07$xo54ftDxdJKeeVZcVm8y9O",    "$2b$07$xo54ftDxdJKeeVZcVm8y9Ojt76V.7dAICUOYkEXHlZpzEEbuTTRpC" },
            // PHP password_hash
            { "test",                               "$2y$10$u3XfEiRife.cNffWS0aD9O",    "$2y$10$u3XfEiRife.cNffWS0aD9OUPdFLVsiedZcGA/fXXeRyZBlvjGyS3e" },
            { "chipsn'dip",                         "$2y$10$9Cb83ULoFHStLMg2iKG3p.",    "$2y$10$9Cb83ULoFHStLMg2iKG3p.0.ux/vJ49gZXs4FMooj44W1P8DN89Pi" },
        };

        private readonly char[] _revisions = { 'a', 'x', 'y', 'b' };


        private readonly string TwoPointZeroVersionPass64 = "585292059d6b430b931e77f046bb20cca5f99e9adc8a4359aadd93afa03e60c3";

        /**
         * Test method for 'BCrypt.HashPassword(string, string)'
         */
        [Fact()]
        public void TestHashPasswordEnhanced()
        {
            Trace.Write("BCrypt.HashPassword(): ");
            var sw = Stopwatch.StartNew();
            for (var r = 0; r < _revisions.Length; r++)
            {
                for (int i = 0; i < _testVectors.Length / 3; i++)
                {
                    string plain = _testVectors[i, 0];

                    //Check hash that goes in one end comes out the next the same
                    string salt = _testVectors[i, 1].Replace("2a", "2" + _revisions[r]);

                    string hashed = BCryptExtendedV3.HashPassword(HMACKey, plain, salt);

                    var revCheck = hashed.StartsWith("$2" + _revisions[r]);

                    Assert.True(revCheck);

                    var validateHashCheck = BCryptExtendedV3.Verify(HMACKey, plain, hashed);
                    Assert.True(validateHashCheck);

                    Trace.WriteLine(hashed);

                    Trace.Write(".");
                }
            }

            Trace.WriteLine(sw.ElapsedMilliseconds);
            Trace.WriteLine("");
        }


        [Fact()]
        public void TestHashPasswordEnhanced_OtherProgrammingLanguagesVectors()
        {
            Trace.Write("BCrypt.HashPassword(): ");
            var sw = Stopwatch.StartNew();

            for (int i = 0; i < _otherLibTestVectors.Length / 3; i++)
            {
                string plain = _otherLibTestVectors[i, 0];

                //Check hash that goes in one end comes out the next the same
                string salt = _otherLibTestVectors[i, 1];

                string hashed = BCryptExtendedV3.HashPassword(HMACKey, plain, salt, HashType.SHA256);

                Assert.Equal(_otherLibTestVectors[i, 2], hashed);

                var validateHashCheck = BCryptExtendedV3.Verify(HMACKey, plain, hashed, HashType.SHA256);
                Assert.True(validateHashCheck);

                Trace.WriteLine(hashed);

                Trace.Write(".");
            }

            Trace.WriteLine(sw.ElapsedMilliseconds);
            Trace.WriteLine("");
        }


        [Fact()]
        public void TestHashPasswordEnhancedWithHashType()
        {
            Trace.Write("BCrypt.HashPassword(): ");
            var sw = Stopwatch.StartNew();
            for (var r = 0; r < _revisions.Length; r++)
            {
                for (int i = 0; i < _testVectors.Length / 3; i++)
                {
                    string plain = _testVectors[i, 0];

                    //Check hash that goes in one end comes out the next the same
                    string salt = _testVectors[i, 1].Replace("2a", "2" + _revisions[r]);

                    string hashed = BCryptExtendedV3.HashPassword(HMACKey, plain, salt, HashType.SHA256);

                    var revCheck = hashed.StartsWith("$2" + _revisions[r]);

                    Assert.True(revCheck);

                    var validateHashCheck = BCryptExtendedV3.Verify(HMACKey, plain, hashed, HashType.SHA256);
                    Assert.True(validateHashCheck);

                    Trace.WriteLine(hashed);

                    Trace.Write(".");
                }
            }

            Trace.WriteLine(sw.ElapsedMilliseconds);
            Trace.WriteLine("");
        }


        [Fact()]
        public void TestValidateAndReplaceWithWorkload()
        {
            for (int i = 0; i < 6 / 3; i++)
            {
                string currentKey = _testVectors[i, 0];
                string salt = _testVectors[i, 1];
                string currentHash = _testVectors[i, 2];

                string newPassword = "my new password";
                string hashed = BCrypt.HashPassword(currentKey, salt);
                var d = hashed == currentHash;

                var newHash = BCrypt.ValidateAndUpgradeHash(currentKey, currentHash, newPassword, workFactor: 11);

                var newPassValid = BCrypt.Verify(newPassword, newHash);

                Assert.True(newPassValid);
                Assert.Contains("$11$", newHash);

                Trace.Write(".");
            }

        }

        [Fact()]
        public void TestValidateAndReplaceWithWorkloadSmallerThanCurrentEndsWithSameWorkLoadAsOriginalHash()
        {

            string currentKey = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
            string salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
            string currentHash = "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC";

            string newPassword = "my new password";
            string hashed = BCrypt.HashPassword(currentKey, salt);
            var d = hashed == currentHash;

            Assert.Contains("$12$", BCrypt.ValidateAndUpgradeHash(currentKey, currentHash, newPassword, workFactor: 5));

            Trace.Write(".");
        }

        [Fact()]
        public void TestValidateAndReplaceWithForceAndWorkloadSmallerThanCurrentEndsWithRequestedWorkLoad()
        {
            string currentKey = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
            string salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
            string currentHash = "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC";

            string newPassword = "my new password";
            string hashed = BCrypt.HashPassword(currentKey, salt);
            Assert.Equal(hashed, currentHash);
            var replHash = BCrypt.ValidateAndUpgradeHash(currentKey, currentHash, newPassword, workFactor: 5, forceWorkFactor: true);
            Assert.Contains("$05$", replHash);
            Trace.Write(".");
        }


        /**
         * Test method for 'BCrypt.GenerateSalt(int)'
         */
        [Fact()]
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
                    Assert.Equal(hashed1, hashed2);
                    Trace.Write(".");
                }
            }
            Trace.WriteLine("");
        }

        [Fact(Skip = "This test takes a very long time to run as it uses the max workload")]
        public void TestGenerateSaltWithMaxWorkFactor()
        {
            Trace.Write("BCrypt.GenerateSalt(31):");
            for (int j = 0; j < _testVectors.Length / 3; j++)
            {
                string plain = _testVectors[j, 0];
                string salt = BCrypt.GenerateSalt(31);
                string hashed1 = BCrypt.HashPassword(plain, salt);
                string hashed2 = BCrypt.HashPassword(plain, hashed1);
                Assert.Equal(hashed1, hashed2);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.GenerateSalt()'
         */
        [Fact()]
        public void TestGenerateSalt()
        {
            Trace.Write("BCrypt.GenerateSalt():");
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                string plain = _testVectors[i, 0];
                string salt = BCrypt.GenerateSalt();
                string hashed1 = BCrypt.HashPassword(plain, salt);
                string hashed2 = BCrypt.HashPassword(plain, hashed1);
                Assert.Equal(hashed1, hashed2);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.VerifyPassword(string, string)'
         * expecting success
         */
        [Fact()]
        public void TestVerifyPasswordSuccess()
        {
            Trace.Write("BCrypt.Verify with good passwords:");
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                string plain = _testVectors[i, 0];
                string expected = _testVectors[i, 2];
                Assert.True(BCrypt.Verify(plain, expected));
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test method for 'BCrypt.VerifyPassword(string, string)'
         * expecting failure
         */
        [Fact()]
        public void TestVerifyPasswordFailure()
        {
            Trace.Write("BCrypt.Verify with bad passwords: ");
            for (int i = 0; i < _testVectors.Length / 3; i++)
            {
                int brokenIndex = (i + 4) % (_testVectors.Length / 3);
                string plain = _testVectors[i, 0];
                string expected = _testVectors[brokenIndex, 2];
                var res = BCrypt.Verify(plain, expected);
                Assert.False(res);
                Trace.Write(".");
            }
            Trace.WriteLine("");
        }

        /**
         * Test for correct hashing of non-US-ASCII passwords
         */
        [Theory()]
        [InlineData("\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605")]
        [InlineData("ππππππππ")]
        public void TestInternationalChars(string pw1)
        {
            Trace.Write("BCrypt.HashPassword with international chars: ");
            string pw2 = "????????";

            string h1 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt());
            Assert.False(BCrypt.Verify(pw2, h1));
            Trace.Write(".");

            string h2 = BCrypt.HashPassword(pw2, BCrypt.GenerateSalt());
            Assert.False(BCrypt.Verify(pw1, h2));
            Trace.Write(".");
            Trace.WriteLine("");
        }


        [Theory()]
        [InlineData("RwiKnN>9xg3*C)1AZl.)y8f_:GCz,vt3T]PIV)[7kktZZQ)z1HI(gyrqgn6;gyb]eIP>r1f:<xw?R")]
        [InlineData("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>")]
        [InlineData("ππππππππ")]
        [InlineData("ЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя")]
        [InlineData("ÅÍÎÏ˝ÓÔÒÚÆ☃")]
        [InlineData("사회과학원 어학연구소")]
        [InlineData("ﾟ･✿ヾ╲(｡◕‿◕｡)╱✿･ﾟ")]
        [InlineData("👾 🙇 💁 🙅 🙆 🙋 🙎 🙍")]
        public void TestNaughtyStringsHash(string pw1)
        {
            Trace.Write("BCrypt.HashPassword with naughty strings: ");

            string h1 = BCrypt.HashPassword(pw1, BCrypt.GenerateSalt());
            Assert.True(BCrypt.Verify(pw1, h1));

            Trace.Write(".");
        }

        [Theory()]
        [InlineData("password\0defgreallylongpassword")]
        [InlineData("password\x00 xdefgreallylongpassword")]
        [InlineData("password\x00 defgreallylongpassword")]
        public void NullTerminationCausesBCryptToTerminateStringInSomeFrameworks(string password)
        {
            var x = BCrypt.GenerateSalt();
            string hash = BCrypt.HashPassword(password, x);

            var t1 = BCrypt.Verify(password, hash);
            var t2 = BCrypt.Verify("password", hash);
            Assert.True(t1, "Null terminator should validate if part of passphrase");
            Assert.False(t2, "Null terminator shouldn't alter passphrase");
        }

        [Theory()]
        [InlineData("\0 defgreallylongpassword", "\0")]
        public void NullTerminationCausesBCryptToTerminateStringInSomeFrameworksSetB(string password, string leader)
        {
            var x = BCrypt.GenerateSalt();
            string hash = BCrypt.HashPassword(password, x);

            Assert.False(BytesAreValid(SafeUtf8.GetBytes(password)));

            var t1 = BCrypt.Verify(leader, hash);
            Assert.False(t1, "Null should be treated as part of password as per spec");
            Assert.False(BCrypt.Verify("", hash), "Null should be treated as part of password as per spec");

        }

        [Fact]
        public void LeadingByteDoesntTruncateHash()
        {
            var b = new BCryptCore();
            var s = BCrypt.GenerateSalt();
            var extractedSalt = s.Substring(7, 22);

            var passA = SafeUtf8.GetBytes("\0 password");
            var passB = SafeUtf8.GetBytes("\0");

            byte[] saltBytes = BCryptCore.DecodeBase64(extractedSalt, 128 / 8);

            var bytesAreValid = BytesAreValid(passA);
            Assert.False(bytesAreValid, "Hash contains null bytes");

            var hashA = b.CryptRaw(passA, saltBytes, 4);
            var hashAVerification = b.CryptRaw(passA, saltBytes, 4);
            Assert.True(Convert.ToBase64String(hashA) == Convert.ToBase64String(hashAVerification), "These should match as this is how validation works");

            var hashB = b.CryptRaw(passB, saltBytes, 4);
            var hashBVerification = b.CryptRaw(passB, saltBytes, 4);
            Assert.True(Convert.ToBase64String(hashB) == Convert.ToBase64String(hashBVerification), "These should match as this is how validation works, this is skipping the password");

            Assert.False(Convert.ToBase64String(hashA) == Convert.ToBase64String(hashB), "These shouldn't match as we hash the whole strings bytes, including the null byte");
        }

        [Fact]
        public void LeadingByteDoesntTruncateHashSHA()
        {
            var b = new BCrypt();
            var s = BCrypt.GenerateSalt();
            var extractedSalt = s.Substring(7, 22);

            var passA = SafeUtf8.GetBytes("d27a37");
            var passB = new byte[] { 0 };

            byte[] saltBytes = BCrypt.DecodeBase64(extractedSalt, 128 / 8);

            var sha = new HMACSHA256(SafeUtf8.GetBytes(HMACKey));
            byte[] enhancedBytes = sha.ComputeHash(passA);
            byte[] enhancedBytesB = sha.ComputeHash(passB);

            var bytesAreValid = BytesAreValid(enhancedBytes);
            Assert.False(bytesAreValid, "Hash contains null bytes");

            var hashA = b.CryptRaw(enhancedBytes, saltBytes, 4);
            var hashAVerification = b.CryptRaw(enhancedBytes, saltBytes, 4);
            Assert.True(Convert.ToBase64String(hashA) == Convert.ToBase64String(hashAVerification), "These should match as this is how validation works");

            var hashB = b.CryptRaw(enhancedBytesB, saltBytes, 4);
            var hashBVerification = b.CryptRaw(enhancedBytesB, saltBytes, 4);
            Assert.True(Convert.ToBase64String(hashB) == Convert.ToBase64String(hashBVerification), "These should match as this is how validation works");

            Assert.False(Convert.ToBase64String(hashA) == Convert.ToBase64String(hashB), "These shouldnt match as we hash the whole strings bytes, including the null byte");
        }

        private static bool BytesAreValid(byte[] bytes)
        {
            if (bytes == null) return false;
            return !Array.Exists(bytes, x => x == 0);
        }

        [Theory]
        [InlineData("$2$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", "$2$06", "2", "06", "DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.")]
        [InlineData("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", "$2a$06", "2a", "06", "DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.")]
        [InlineData("$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye", "$2a$08", "2a", "08", "HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye")]
        public void InterrogateHash_WhenHashIsValid_ParsesHash(string hash, string settings, string version, string workFactor, string rawHash)
        {
            var hashInformation = BCrypt.InterrogateHash(hash);

            Assert.Equal(settings, hashInformation.Settings);
            Assert.Equal(version, hashInformation.Version);
            Assert.Equal(workFactor, hashInformation.WorkFactor.ToString("D2"));
            Assert.Equal(rawHash, hashInformation.RawHash);
        }

        [Theory]
        [InlineData("")]
        [InlineData("asdasdasldkfhja;sldgkja;sldgkjasdg")] // Jibberish
        [InlineData("$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/Sg")] // Too short
        [InlineData("$2a$-1$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye")] // Strange workfactor
        [InlineData("$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUty!")] // Invalid base64 character
        [InlineData("$2a$08aHqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye")] // Invalid hash layout
        [InlineData("$2ac08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye")] // Invalid hash layout
        [InlineData("a2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye")] // Invalid hash layout
        public void InterrogateHash_WhenHashInvalid_ThrowsInvalidHashFormat(string hash)
        {
            var exception = Assert.Throws<HashInformationException>(() => BCrypt.InterrogateHash(hash));

            var saltParseException = Assert.IsType<SaltParseException>(exception.InnerException);

            Assert.Equal("Invalid Hash Format", saltParseException.Message);
        }

        [Theory]
        [InlineData("$2$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", 8, true)]
        [InlineData("$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye", 10, true)]
        [InlineData("$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye", 6, false)]
        public void PasswordNeedsRehash_ComparesWorkFactorInHashWithGiven(string hash, int newWorkFactor, bool expected)
        {
            bool needsRehash = BCrypt.PasswordNeedsRehash(hash, newWorkFactor);

            Assert.Equal(expected, needsRehash);
        }
    }
#endif
}
