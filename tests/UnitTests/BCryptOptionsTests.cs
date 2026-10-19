/*
The MIT License (MIT)
Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
Copyright (c) 2013 Ryan D. Emerle (.Net port)
Copyright (c) 2016/2026 Chris McKee (.Net-core port / patches / new features)

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
using Xunit;

namespace BCryptNet.UnitTests
{
    public class BCryptOptionsTests
    {
        private const string Salt = "$2a$04$abcdefghijklmnopqrstuu";
        private const string Punctuation = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";

        // 300 x U+0416 encodes to 600 UTF-8 bytes, exercising the pooled (non-stackalloc) buffer path
        private static readonly string LongUnicode = new string('Ж', 300);

        [Fact]
        public void Default_MatchesLibraryDefaults()
        {
            BCryptOptions options = default;

            Assert.Equal(11, options.WorkFactor);
            Assert.Equal(LongPasswordHandling.Throw, options.LongPasswordHandling);
            Assert.Null(options.PreHash);
            Assert.Equal(BCryptOptions.Default, options);
            Assert.Equal(new BCryptOptions(), options);
        }

        [Fact]
        public void Equality_TreatsNullWorkFactorAsDefault()
        {
            Assert.Equal(new BCryptOptions(11), new BCryptOptions(null));
            Assert.Equal(new BCryptOptions(11), new BCryptOptions(12).WithWorkFactor(null));
            Assert.True(new BCryptOptions(11) == default);
            Assert.True(new BCryptOptions(12) != default);
            Assert.Equal(new BCryptOptions(11).GetHashCode(), default(BCryptOptions).GetHashCode());
            Assert.NotEqual(new BCryptOptions(preHash: HashType.SHA256), new BCryptOptions(preHash: HashType.SHA384));
        }

        [Fact]
        public void With_ReturnsModifiedCopy()
        {
            var original = new BCryptOptions(5);
            var modified = original.WithLongPasswordHandling(LongPasswordHandling.Truncate).WithPreHash(HashType.SHA512).WithWorkFactor(6);

            Assert.Equal(5, original.WorkFactor);
            Assert.Equal(LongPasswordHandling.Throw, original.LongPasswordHandling);
            Assert.Equal(new BCryptOptions(6, LongPasswordHandling.Truncate, HashType.SHA512), modified);

            // An unset work factor stays unset rather than being passed on as an (invalid) explicit 0
            var unset = default(BCryptOptions).WithLongPasswordHandling(LongPasswordHandling.Truncate).WithPreHash(HashType.SHA512);
            Assert.Equal(new BCryptOptions(null, LongPasswordHandling.Truncate, HashType.SHA512), unset);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(3)]
        [InlineData(32)]
        public void Constructor_RejectsOutOfRangeWorkFactor(int workFactor)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptOptions(workFactor));
            Assert.Throws<ArgumentOutOfRangeException>(() => default(BCryptOptions).WithWorkFactor(workFactor));
        }

        [Fact]
        public void Constructor_RejectsUndefinedEnums()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptOptions(longPasswordHandling: (LongPasswordHandling)2));
            Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptOptions(preHash: (HashType)3));
            Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptOptions(preHash: (HashType)(-2)));
        }

        [Fact]
        public void HashPassword_UsesOptionsWorkFactor()
        {
            var hash = BCrypt.HashPassword("password", new BCryptOptions(5));

            Assert.StartsWith("$2a$05$", hash);
            Assert.True(BCrypt.Verify("password", hash));
        }

        [Fact]
        public void HashPassword_WithSalt_IgnoresOptionsWorkFactor()
        {
            Assert.Equal(BCrypt.HashPassword("password", Salt), BCrypt.HashPassword("password", Salt, new BCryptOptions(12)));
        }

        [Fact]
        public void LongPasswordHandling_FlowsThroughVerifyAndUpgrade()
        {
            var truncate = new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate);
            var sharedPrefix = new string('x', 70) + "π";
            var firstPassword = sharedPrefix + "a";
            var secondPassword = sharedPrefix + "b";

            var hash = BCrypt.HashPassword(firstPassword, Salt, truncate);

            Assert.Throws<PasswordTooLongException>(() => BCrypt.HashPassword(firstPassword, Salt));
            Assert.Throws<PasswordTooLongException>(() => BCrypt.Verify(secondPassword, hash));
            Assert.True(BCrypt.Verify(secondPassword, hash, truncate));

            var upgradedHash = BCrypt.ValidateAndUpgradeHash(firstPassword, hash, secondPassword, truncate.WithWorkFactor(5), forceWorkFactor: true);
            Assert.StartsWith("$2a$05$", upgradedHash);
            Assert.True(BCrypt.Verify(firstPassword, upgradedHash, truncate));
            Assert.Throws<PasswordTooLongException>(() =>
                BCrypt.ValidateAndUpgradeHash(firstPassword, hash, secondPassword, new BCryptOptions(5)));
        }

#if NETCOREAPP
        [Fact]
        public void LongPasswordHandling_FlowsThroughSpanAndBufferApis()
        {
            var truncate = new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate);
            var password = new string('x', 80);
            var expected = BCrypt.HashPassword(password, Salt, truncate);

            Assert.Equal(expected, BCrypt.HashPassword(password.AsSpan(), Salt.AsSpan(), truncate));
            Assert.Throws<PasswordTooLongException>(() => BCrypt.HashPassword(password.AsSpan(), Salt.AsSpan()));

            Span<char> outputBuffer = stackalloc char[60];
            BCrypt.HashPassword(password.AsSpan(), Salt.AsSpan(), outputBuffer, out var written, truncate);
            Assert.Equal(expected, new string(outputBuffer[..written]));
            Assert.True(BCrypt.Verify(password.AsSpan(), expected.AsSpan(), truncate));
        }
#endif

#if SECURESTRING
        [Fact]
        public void LongPasswordHandling_FlowsThroughSecureString()
        {
            var truncate = new BCryptOptions(longPasswordHandling: LongPasswordHandling.Truncate);
            var securePassword = new System.Security.SecureString();
            foreach (char c in new string('x', 80))
            {
                securePassword.AppendChar(c);
            }

            var hash = BCryptSafeString.HashPassword(securePassword, Salt, truncate);

            Assert.Equal(BCrypt.HashPassword(new string('x', 80), Salt, truncate), hash);
            Assert.True(BCryptSafeString.Verify(securePassword, hash, truncate));
            Assert.Throws<PasswordTooLongException>(() => BCryptSafeString.HashPassword(securePassword, Salt));
            Assert.StartsWith("$2a$05$", BCryptSafeString.HashPassword(securePassword, truncate.WithWorkFactor(5)));
        }
#endif

        [Fact]
        public void BCrypt_RejectsPreHash()
        {
            Assert.Throws<ArgumentException>(() => BCrypt.HashPassword("password", Salt, new BCryptOptions(preHash: HashType.SHA384)));
            Assert.Throws<ArgumentException>(() => BCrypt.Verify("password", BCrypt.HashPassword("password", Salt), new BCryptOptions(preHash: HashType.SHA384)));

            // None is the explicit "no pre-hash" value and is accepted
            Assert.Equal(BCrypt.HashPassword("password", Salt), BCrypt.HashPassword("password", Salt, new BCryptOptions(preHash: HashType.None)));
        }

        // Vectors generated by the release prior to BCryptOptions (commit f80f987); pre-hash output must not change.
        [Theory]
        [InlineData(Punctuation, HashType.SHA256, "$2a$04$abcdefghijklmnopqrstuuRRqd.L5yNA70.H5F0OlUq.O7ViqcGU6")]
        [InlineData(Punctuation, HashType.SHA384, "$2a$04$abcdefghijklmnopqrstuuCiPrZJuZrg4O4VJUQCYDFhSMjgMv7/W")]
        [InlineData(Punctuation, HashType.SHA512, "$2a$04$abcdefghijklmnopqrstuully1N/z0YtISjMDp7iK55zcu1EDIAZS")]
        [InlineData(null, HashType.SHA256, "$2a$04$abcdefghijklmnopqrstuuul8HQv.llbV0RipAjYTRy3i9kpwMAqq")]
        [InlineData(null, HashType.SHA384, "$2a$04$abcdefghijklmnopqrstuudLo6m9G0EiVmJrXv7T1aATfLvflcLcG")]
        [InlineData(null, HashType.SHA512, "$2a$04$abcdefghijklmnopqrstuuNG.EVEAyRXEaxZSRNl4X9Sa0wl9y3JW")]
        public void ExtendedV2_MatchesPreviousReleaseVectors(string password, HashType hashType, string expected)
        {
            password ??= LongUnicode;
            var options = new BCryptOptions(preHash: hashType);

            Assert.Equal(expected, BCryptExtendedV2.HashPassword(password, Salt, options));
            Assert.True(BCryptExtendedV2.Verify(password, expected, options));
            Assert.False(BCryptExtendedV2.Verify(password + "x", expected, options));
        }

        [Fact]
        public void ExtendedV2_DefaultsToSha384()
        {
            Assert.Equal(BCryptExtendedV2.HashPassword(Punctuation, Salt, new BCryptOptions(preHash: HashType.SHA384)),
                BCryptExtendedV2.HashPassword(Punctuation, Salt));
        }

        [Fact]
        public void ExtendedV2_RejectsNoPreHash()
        {
            var none = new BCryptOptions(preHash: HashType.None);
            var hash = BCryptExtendedV2.HashPassword("password", Salt);

            Assert.Throws<ArgumentException>(() => BCryptExtendedV2.HashPassword("password", none));
            Assert.Throws<ArgumentException>(() => BCryptExtendedV2.HashPassword("password", Salt, none));
            Assert.Throws<ArgumentException>(() => BCryptExtendedV2.Verify("password", hash, none));

            // Options are validated before the credentials are checked
            Assert.Throws<ArgumentException>(() => BCryptExtendedV2.ValidateAndUpgradeHash("wrong", hash, "new", none));
        }

        [Fact]
        public void ExtendedV2_UpgradesTruncatedPlainBcryptHash()
        {
            var truncate = new BCryptOptions(5, LongPasswordHandling.Truncate);
            var longPassword = new string('x', 80);
            var legacyHash = BCrypt.HashPassword(longPassword, Salt, truncate);

            var upgraded = BCryptExtendedV2.ValidateAndUpgradeHash(longPassword, legacyHash, HashType.None, "new password", truncate);

            Assert.StartsWith("$2a$05$", upgraded);
            Assert.True(BCryptExtendedV2.Verify("new password", upgraded));
            Assert.Throws<BcryptAuthenticationException>(() =>
                BCryptExtendedV2.ValidateAndUpgradeHash("wrong", legacyHash, HashType.None, "new password", truncate));

            // Without the policy the legacy hash can't be verified
            Assert.Throws<PasswordTooLongException>(() =>
                BCryptExtendedV2.ValidateAndUpgradeHash(longPassword, legacyHash, HashType.None, "new password", new BCryptOptions(5)));
        }

#if NETCOREAPP
        private const string V3Salt = "$2b$05$XXXXXXXXXXXXXXXXXXXXXO";
        private const string HmacKey = "hmac-key-é";

        // Vectors generated by the release prior to BCryptOptions (commit f80f987); pre-hash output must not change.
        [Theory]
        [InlineData(Punctuation, HmacKey, HashType.SHA256, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOjJ07VCtqI8WGz4aDeNbiA1Xqcywodc6")]
        [InlineData(Punctuation, HmacKey, HashType.SHA384, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOIfRSyW0.mdsf8NYeYMr/tEkIkm0V1ji")]
        [InlineData(Punctuation, HmacKey, HashType.SHA512, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOPIQLpcRq9Gt3zL5E7rZpWw35zSf7jqm")]
        [InlineData(Punctuation, null, HashType.SHA384, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOxsETFP8J8RM6aQrbPmMImhiL81s9o5q")]
        [InlineData(null, HmacKey, HashType.SHA384, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOxyjAQ1o6JqQd68Gb39ndpGN1TeZG2JC")]
        [InlineData(null, null, HashType.SHA384, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOswOOnVyym3sJxNtcHawOJ4pGsvFOUXC")]
        public void ExtendedV3_MatchesPreviousReleaseVectors(string password, string hmacKey, HashType hashType, string expected)
        {
            password ??= LongUnicode;
            hmacKey ??= new string('k', 400); // longer than the stackalloc threshold
            var options = new BCryptOptions(preHash: hashType);

            Assert.Equal(expected, BCryptExtendedV3.HashPassword(hmacKey, password, V3Salt, options));
            Assert.True(BCryptExtendedV3.Verify(hmacKey, password, expected, options));
            Assert.False(BCryptExtendedV3.Verify(hmacKey + "x", password, expected, options));
        }

        [Fact]
        public void ExtendedV3_RejectsNullHmacKey()
        {
            Assert.Throws<ArgumentNullException>(() => BCryptExtendedV3.HashPassword(null, "password", V3Salt));
            Assert.Throws<ArgumentNullException>(() => BCryptExtendedV3.HashPassword(null, "password", new BCryptOptions(4)));
            Assert.Throws<ArgumentNullException>(() => BCryptExtendedV3.Verify(null, "password", "$2b$05$XXXXXXXXXXXXXXXXXXXXXOjJ07VCtqI8WGz4aDeNbiA1Xqcywodc6"));
        }

        [Fact]
        public void ExtendedV3_RejectsNoPreHash()
        {
            var none = new BCryptOptions(preHash: HashType.None);
            var hash = BCryptExtendedV3.HashPassword(HmacKey, "password", V3Salt);

            // HashType.None would bypass the HMAC and silently drop the key
            Assert.Throws<ArgumentException>(() => BCryptExtendedV3.HashPassword(HmacKey, "password", none));
            Assert.Throws<ArgumentException>(() => BCryptExtendedV3.HashPassword(HmacKey, "password", V3Salt, none));
            Assert.Throws<ArgumentException>(() => BCryptExtendedV3.HashPassword(HmacKey, "password".AsSpan(), V3Salt.AsSpan(), none));
            Assert.Throws<ArgumentException>(() => BCryptExtendedV3.Verify(HmacKey, "password", hash, none));
            Assert.Throws<ArgumentException>(() => BCryptExtendedV3.ValidateAndUpgradeHash(HmacKey, "wrong", hash, "new", none));
        }

        [Fact]
        public void ExtendedV3_UpgradesTruncatedPlainBcryptHash()
        {
            var truncate = new BCryptOptions(5, LongPasswordHandling.Truncate);
            var longPassword = new string('x', 80);
            var legacyHash = BCrypt.HashPassword(longPassword, Salt, truncate);

            var upgraded = BCryptExtendedV3.ValidateAndUpgradeHash(HmacKey, longPassword, legacyHash, HashType.None, "new password", truncate);

            Assert.StartsWith("$2a$05$", upgraded);
            Assert.True(BCryptExtendedV3.Verify(HmacKey, "new password", upgraded));
            Assert.False(BCryptExtendedV3.Verify(HmacKey + "x", "new password", upgraded));
            Assert.Throws<PasswordTooLongException>(() =>
                BCryptExtendedV3.ValidateAndUpgradeHash(HmacKey, longPassword, legacyHash, HashType.None, "new password", new BCryptOptions(5)));
        }

        [Fact]
        public void ExtendedV3_VerifyRejectsOverlongHash()
        {
            Assert.False(BCryptExtendedV3.Verify(HmacKey, Punctuation, "$2b$05$XXXXXXXXXXXXXXXXXXXXXOjJ07VCtqI8WGz4aDeNbiA1Xqcywodc6" + "extra"));
        }
#endif
    }
}
