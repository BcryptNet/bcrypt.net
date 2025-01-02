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
        public void TestValidateAndReplaceWithWorkloadSmallerThanCurrentEndsWithSameWorkLoadAsOriginalHash()
        {
            var hmacKey = Guid.Parse("BFD57646-9EC2-4ED2-A98D-1CE7107D2E38").ToString();

            string currentKey = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
            string salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
            string currentHash = "$2a$12$WApznUOJfkEGSmYRfnkrPO/jMqrnJc5PFWasgccSlw6RlvYsWV4sS";

            string newPassword = "my new password";
            string hashed = BCryptExtendedV3.HashPassword(hmacKey,currentKey, salt);
            string hashed2 = BCryptExtendedV3.HashPassword(hmacKey,currentKey, salt);
            string hashed3 = BCryptExtendedV3.HashPassword(hmacKey,currentKey, salt);
            var d = hashed == currentHash;

            Assert.Contains("$12$", BCryptExtendedV3.ValidateAndUpgradeHash(hmacKey,currentKey, currentHash, newPassword, workFactor: 5));

            Trace.Write(".");
        }

        [Fact()]
        public void TestValidateAndReplaceWithForceAndWorkloadSmallerThanCurrentEndsWithRequestedWorkLoad()
        {
            var hmacKey = Guid.Parse("BFD57646-9EC2-4ED2-A98D-1CE7107D2E38").ToString();

            string currentKey = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
            string salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
            string currentHash = "$2a$12$WApznUOJfkEGSmYRfnkrPO/jMqrnJc5PFWasgccSlw6RlvYsWV4sS";

            string newPassword = "my new password";
            string hashed = BCryptExtendedV3.HashPassword(hmacKey,currentKey, salt);
            Assert.Equal(hashed, currentHash);
            var replHash = BCryptExtendedV3.ValidateAndUpgradeHash(hmacKey, currentKey, currentHash, newPassword, workFactor: 5, forceWorkFactor: true);
            Assert.Contains("$05$", replHash);
            Trace.Write(".");
        }

        /**
         * Test for correct hashing of non-US-ASCII passwords
         */
        [Theory()]
        [InlineData("\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605")]
        [InlineData("ππππππππ")]
        public void TestInternationalChars(string pw1)
        {
            var hmacKey = Guid.NewGuid().ToString();
            Trace.Write("BCrypt.HashPassword with international chars: ");
            string pw2 = "????????";

            string h1 = BCryptExtendedV3.HashPassword(hmacKey,pw1, BCrypt.GenerateSalt());
            Assert.False(BCryptExtendedV3.Verify(hmacKey,pw2, h1));
            Trace.Write(".");

            string h2 = BCryptExtendedV3.HashPassword(hmacKey,pw2, BCrypt.GenerateSalt());
            Assert.False(BCryptExtendedV3.Verify(hmacKey,pw1, h2));
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
            var hmacKey = Guid.NewGuid().ToString();

            string h1 = BCryptExtendedV3.HashPassword(hmacKey,pw1, BCrypt.GenerateSalt());
            Assert.True(BCryptExtendedV3.Verify(hmacKey,pw1, h1));

            Trace.Write(".");
        }

        [Theory()]
        [InlineData("password\0defgreallylongpassword")]
        [InlineData("password\x00 xdefgreallylongpassword")]
        [InlineData("password\x00 defgreallylongpassword")]
        public void NullTerminationCausesBCryptToTerminateStringInSomeFrameworks(string password)
        {
            var hmacKey = Guid.NewGuid().ToString();
            var x = BCryptExtendedV3.GenerateSalt();
            string hash = BCryptExtendedV3.HashPassword(hmacKey,password, x);

            var t1 = BCryptExtendedV3.Verify(hmacKey,password, hash);
            var t2 = BCryptExtendedV3.Verify(hmacKey,"password", hash);
            Assert.True(t1, "Null terminator should validate if part of passphrase");
            Assert.False(t2, "Null terminator shouldn't alter passphrase");
        }

        [Theory()]
        [InlineData("\0 defgreallylongpassword", "\0")]
        public void NullTerminationCausesBCryptToTerminateStringInSomeFrameworksSetB(string password, string leader)
        {
            var hmacKey = Guid.NewGuid().ToString();
            var x = BCryptExtendedV3.GenerateSalt();
            string hash = BCryptExtendedV3.HashPassword(hmacKey,password, x);

            Assert.False(ContainsNoNullBytes(SafeUtf8.GetBytes(password)));

            var t1 = BCryptExtendedV3.Verify(hmacKey,leader, hash);
            Assert.False(t1, "Null should be treated as part of password as per spec");
            Assert.False(BCryptExtendedV3.Verify(hmacKey,"", hash), "Null should be treated as part of password as per spec");
        }

        [Fact]
        public void LeadingByteDoesntTruncateHashSHA()
        {
            var hmacKey = Guid.Parse("5FDEBC5A-C3DD-4DAD-8DB1-26BB439EDD31").ToString();
            var b = new BCrypt();
            var s = BCrypt.GenerateSalt();
            var extractedSalt = s.Substring(7, 22);

            var passA = SafeUtf8.GetBytes("d27a37");
            var passB = new byte[] { 0 };

            byte[] saltBytes = BCrypt.DecodeBase64(extractedSalt, 128 / 8);

            byte[] enhancedBytes = new HMACSHA3_256(SafeUtf8.GetBytes(hmacKey)).ComputeHash(passA);
            byte[] enhancedBytesB = new HMACSHA3_256(SafeUtf8.GetBytes(hmacKey)).ComputeHash(passB);

            var hashA = b.CryptRaw(enhancedBytes, saltBytes, 4);
            var hashAVerification = b.CryptRaw(enhancedBytes, saltBytes, 4);
            Assert.True(Convert.ToBase64String(hashA) == Convert.ToBase64String(hashAVerification), "These should match as this is how validation works");

            var hashB = b.CryptRaw(enhancedBytesB, saltBytes, 4);
            var hashBVerification = b.CryptRaw(enhancedBytesB, saltBytes, 4);
            Assert.True(Convert.ToBase64String(hashB) == Convert.ToBase64String(hashBVerification), "These should match as this is how validation works");

            Assert.False(Convert.ToBase64String(hashA) == Convert.ToBase64String(hashB), "These shouldnt match as we hash the whole strings bytes, including the null byte");
        }

        private static bool ContainsNoNullBytes(byte[] bytes)
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
