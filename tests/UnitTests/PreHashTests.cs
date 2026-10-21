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
    public class PreHashTests
    {
        private const string Salt = "$2a$04$abcdefghijklmnopqrstuu";
        private static readonly BCryptOptions Sha2 = new(4, preHash: PreHash.Sha2());

        [Fact]
        public void Default_IsNone()
        {
            PreHash preHash = default;

            Assert.Equal(PreHash.None, preHash);
            Assert.Equal(PreHashScheme.None, preHash.Scheme);
            Assert.Equal(HashType.None, preHash.HashType);
            Assert.False(preHash.RequiresKey);
            Assert.True(preHash.IsSupported);
            Assert.Equal("None", preHash.ToString());
        }

        [Fact]
        public void Factories_DefaultToSha384()
        {
            Assert.Equal(PreHash.Sha2(HashType.SHA384), PreHash.Sha2());
            Assert.Equal(PreHash.HmacSha3(HashType.SHA384), PreHash.HmacSha3());
            Assert.Equal(HashType.SHA512, PreHash.Sha2(HashType.SHA512).HashType);
            Assert.Equal("HmacSha3-SHA256", PreHash.HmacSha3(HashType.SHA256).ToString());
        }

        [Fact]
        public void Equality_ComparesSchemeAndDigest()
        {
            Assert.True(PreHash.Sha2() == PreHash.Sha2(HashType.SHA384));
            Assert.True(PreHash.Sha2() != PreHash.HmacSha3());
            Assert.True(PreHash.Sha2(HashType.SHA256) != PreHash.Sha2(HashType.SHA512));
            Assert.Equal(PreHash.HmacSha3().GetHashCode(), PreHash.HmacSha3(HashType.SHA384).GetHashCode());
        }

        [Fact]
        public void RequiresKey_OnlyForHmac()
        {
            Assert.False(PreHash.Sha2().RequiresKey);
            Assert.True(PreHash.HmacSha3().RequiresKey);
            Assert.True(PreHash.Sha2().IsSupported);
        }

        [Fact]
        public void HmacKey_RejectsEmpty()
        {
            Assert.Throws<ArgumentException>(() => HmacKey.FromString(""));
            Assert.Throws<ArgumentException>(() => HmacKey.FromBytes(ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public void HmacKey_ToStringIsRedacted()
        {
            using var key = HmacKey.FromString("secret pepper");

            Assert.DoesNotContain("secret", key.ToString());
        }

        [Fact]
        public void Upgrade_PlainToSha2()
        {
            var plain = BCrypt.HashPassword("password", Salt);

            var upgraded = BCrypt.ValidateAndUpgradeHash("password", plain, PreHash.None, "new password", Sha2);

            Assert.True(BCryptExtendedV2.Verify("new password", upgraded));
            Assert.False(BCrypt.Verify("new password", upgraded));
        }

        [Fact]
        public void Upgrade_NeverLowersWorkFactorUnlessForced()
        {
            var current = BCryptExtendedV2.HashPassword("password", "$2a$06$abcdefghijklmnopqrstuu");

            Assert.StartsWith("$2a$06$", BCrypt.ValidateAndUpgradeHash("password", current, PreHash.Sha2(), "new", Sha2));
            Assert.StartsWith("$2a$04$", BCrypt.ValidateAndUpgradeHash("password", current, PreHash.Sha2(), "new", Sha2, forceWorkFactor: true));
        }

        [Fact]
        public void Upgrade_RejectsWrongScheme()
        {
            var current = BCryptExtendedV2.HashPassword("password", Salt, new BCryptOptions(preHash: PreHash.Sha2(HashType.SHA256)));

            Assert.Throws<BcryptAuthenticationException>(() =>
                BCrypt.ValidateAndUpgradeHash("password", current, PreHash.Sha2(HashType.SHA384), "new", Sha2));
        }

        [Fact]
        public void Upgrade_RejectsKeyForSchemeThatIgnoresIt()
        {
            using var key = HmacKey.FromString("pepper");
            var current = BCryptExtendedV2.HashPassword("password", Salt);

            // Checked before credentials, so a wrong password still reports the misuse
            Assert.Throws<ArgumentException>(() =>
                BCrypt.ValidateAndUpgradeHash("wrong", current, PreHash.Sha2(), "new", Sha2, currentHmacKey: key));
            Assert.Throws<ArgumentException>(() =>
                BCrypt.ValidateAndUpgradeHash("wrong", current, PreHash.Sha2(), "new", Sha2, newHmacKey: key));
        }

        [Fact]
        public void Upgrade_RejectsNullPasswords()
        {
            var current = BCryptExtendedV2.HashPassword("password", Salt);

            Assert.Throws<ArgumentNullException>(() => BCrypt.ValidateAndUpgradeHash(null, current, PreHash.Sha2(), "new", Sha2));
            Assert.Throws<ArgumentNullException>(() => BCrypt.ValidateAndUpgradeHash("password", current, PreHash.Sha2(), null, Sha2));
        }

#if NETCOREAPP
        private static readonly BCryptOptions Hmac = new(4, preHash: PreHash.HmacSha3());

        [Fact]
        public void Upgrade_Sha2ToHmacSha3()
        {
            using var key = HmacKey.FromString("pepper");
            var current = BCryptExtendedV2.HashPassword("password", Salt);

            var upgraded = BCrypt.ValidateAndUpgradeHash("password", current, PreHash.Sha2(), "new password", Hmac, newHmacKey: key);

            Assert.True(BCryptExtendedV3.Verify(key, "new password", upgraded));
            Assert.False(BCryptExtendedV2.Verify("new password", upgraded));
        }

        [Fact]
        public void Upgrade_RotatesHmacKey()
        {
            using var oldKey = HmacKey.FromString("old pepper");
            using var newKey = HmacKey.FromString("new pepper");
            var current = BCryptExtendedV3.HashPassword(oldKey, "password", Salt);

            var rotated = BCrypt.ValidateAndUpgradeHash("password", current, PreHash.HmacSha3(), "password", Hmac,
                currentHmacKey: oldKey, newHmacKey: newKey);

            Assert.True(BCryptExtendedV3.Verify(newKey, "password", rotated));
            Assert.False(BCryptExtendedV3.Verify(oldKey, "password", rotated));

            // Swapped keys fail closed: the current hash doesn't verify under the new key
            Assert.Throws<BcryptAuthenticationException>(() =>
                BCrypt.ValidateAndUpgradeHash("password", current, PreHash.HmacSha3(), "password", Hmac,
                    currentHmacKey: newKey, newHmacKey: oldKey));
        }

        [Fact]
        public void Upgrade_RequiresKeyForHmacScheme()
        {
            using var key = HmacKey.FromString("pepper");
            var current = BCryptExtendedV3.HashPassword(key, "password", Salt);

            Assert.Throws<ArgumentNullException>(() =>
                BCrypt.ValidateAndUpgradeHash("password", current, PreHash.HmacSha3(), "new", Hmac, newHmacKey: key));
            Assert.Throws<ArgumentNullException>(() =>
                BCrypt.ValidateAndUpgradeHash("password", current, PreHash.HmacSha3(), "new", Hmac, currentHmacKey: key));
        }

        [Fact]
        public void HmacKey_ThrowsOnceDisposed()
        {
            var key = HmacKey.FromString("pepper");
            key.Dispose();
            key.Dispose(); // idempotent

            Assert.Throws<ObjectDisposedException>(() => BCryptExtendedV3.HashPassword(key, "password", Salt));
        }

        [Fact]
        public void HmacKey_FromBytesCopiesInput()
        {
            byte[] bytes = { 1, 2, 3, 4 };
            using var key = HmacKey.FromBytes(bytes);
            var expected = BCryptExtendedV3.HashPassword(key, "password", Salt);

            bytes[0] = 9;

            Assert.Equal(expected, BCryptExtendedV3.HashPassword(key, "password", Salt));
        }
#else
        [Fact]
        public void HmacSha3_NotSupportedPreCore()
        {
            using var key = HmacKey.FromString("pepper");
            var current = BCryptExtendedV2.HashPassword("password", Salt);

            Assert.False(PreHash.HmacSha3().IsSupported);
            Assert.Throws<PlatformNotSupportedException>(() =>
                BCrypt.ValidateAndUpgradeHash("password", current, PreHash.Sha2(), "new",
                    new BCryptOptions(preHash: PreHash.HmacSha3()), newHmacKey: key));
        }
#endif
    }
}
