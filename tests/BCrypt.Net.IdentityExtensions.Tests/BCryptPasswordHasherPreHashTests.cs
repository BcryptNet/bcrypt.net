// /*
// The MIT License (MIT)
// Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
// Copyright (c) 2013 Ryan D. Emerle (.Net port)
// Copyright (c) 2016/2026 Chris McKee (.Net-core port / patches / new features)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
// merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
// */

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using BCryptNet;
using BCryptNet.IdentityExtensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace BCrypt.Net.IdentityExtensions.Tests;

public sealed class BCryptPasswordHasherPreHashTests
{
    private sealed class TestUser;

    private const string Pepper = "pepper";
    private static readonly TestUser User = new();

    private static PreHashOptions Plain => new();
    private static PreHashOptions Sha2 => new() { Scheme = PreHashScheme.Sha2 };
    private static PreHashOptions Hmac(string key = Pepper) => new() { Scheme = PreHashScheme.HmacSha3, HmacKey = key };

    private static BCryptPasswordHasher<TestUser> CreateHasher(PreHashOptions preHash, params PreHashOptions[] previous)
    {
        var options = new BCryptHasherOptions { WorkFactor = 4, PreHash = preHash };
        foreach (var p in previous)
        {
            options.PreviousPreHashes.Add(p);
        }

        return new BCryptPasswordHasher<TestUser>(new PasswordHasher<TestUser>(), Options.Create(options));
    }

    internal static string Untag(string hash, string tag)
    {
        Assert.StartsWith(tag + "$2", hash, StringComparison.Ordinal);
        return hash[tag.Length..];
    }

    [Fact]
    public void Defaults_ToPlainBcrypt()
    {
        var options = new BCryptHasherOptions();

        Assert.Equal(PreHashScheme.None, options.PreHash.Scheme);
        Assert.Equal(HashType.SHA384, options.PreHash.Digest);
        Assert.Empty(options.PreviousPreHashes);
    }

    [Fact]
    public void HashPassword_Sha2_CreatesExtendedV2Hash()
    {
        var hash = Untag(CreateHasher(new PreHashOptions { Scheme = PreHashScheme.Sha2, Digest = HashType.SHA256 }).HashPassword(User, "password"),
            "$bcnet-sha2-256");

        Assert.True(BCryptExtendedV2.Verify("password", hash, new BCryptOptions(preHash: PreHash.Sha2(HashType.SHA256))));
        Assert.False(BCryptNet.BCrypt.Verify("password", hash));
    }

    [Fact]
    public void HashPassword_HmacSha3_CreatesExtendedV3Hash()
    {
        using var key = HmacKey.FromString(Pepper);
        using var wrongKey = HmacKey.FromString("other");

        var hash = Untag(CreateHasher(Hmac()).HashPassword(User, "password"), "$bcnet-hmac-sha3-384");

        Assert.True(BCryptExtendedV3.Verify(key, "password", hash));
        Assert.False(BCryptExtendedV3.Verify(wrongKey, "password", hash));
    }

    [Fact]
    public void VerifyHashedPassword_CurrentScheme()
    {
        var hasher = CreateHasher(Hmac());
        var hash = hasher.HashPassword(User, "password");

        Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(User, hash, "password"));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(User, hash, "wrong"));
    }

    [Fact]
    public void VerifyHashedPassword_OtherSchemeFailsUnlessListed()
    {
        var plainHash = CreateHasher(Plain).HashPassword(User, "password");

        Assert.Equal(PasswordVerificationResult.Failed, CreateHasher(Hmac()).VerifyHashedPassword(User, plainHash, "password"));
    }

    [Fact]
    public void VerifyHashedPassword_PreviousScheme_RequestsRehash()
    {
        var hasher = CreateHasher(Hmac(), Plain, Sha2);
        var plainHash = CreateHasher(Plain).HashPassword(User, "password");
        var sha2Hash = CreateHasher(Sha2).HashPassword(User, "password");

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(User, plainHash, "password"));
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(User, sha2Hash, "password"));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(User, plainHash, "wrong"));

        // As Identity would: re-hash, then verify under the current scheme
        var upgraded = hasher.HashPassword(User, "password");
        Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(User, upgraded, "password"));
    }

    [Fact]
    public void VerifyHashedPassword_RotatesHmacKey()
    {
        var oldHash = CreateHasher(Hmac("old pepper")).HashPassword(User, "password");
        var hasher = CreateHasher(Hmac("new pepper"), Hmac("old pepper"));

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(User, oldHash, "password"));
        Assert.Equal(PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(User, hasher.HashPassword(User, "password"), "password"));
    }

    [Fact]
    public void VerifyHashedPassword_LongPasswordAgainstPreviousPlainScheme_Fails()
    {
        // A wrong long password must fail, not throw, in the plain fallback
        var hasher = CreateHasher(Hmac(), Plain);
        var hash = hasher.HashPassword(User, new string('x', 100));

        Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(User, hash, new string('x', 100)));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(User, hash, new string('y', 100)));
    }

    [Fact]
    public void VerifyHashedPassword_WorkFactorRehashStillApplies()
    {
        var options = new BCryptHasherOptions { WorkFactor = 5, RehashPasswords = true, PreHash = Sha2 };
        var hasher = new BCryptPasswordHasher<TestUser>(new PasswordHasher<TestUser>(), Options.Create(options));
        var lowCost = "$bcnet-sha2-384" + BCryptExtendedV2.HashPassword("password", 4);

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(User, lowCost, "password"));
    }

    [Fact]
    public void VerifyHashedPassword_Sha2HashUnderPlainFallback_RejectsDigestAsPassword()
    {
        // A leaked unsalted SHA384 of the password must not log in
        var hasher = CreateHasher(Hmac(), Plain, Sha2);
        var sha2Hash = CreateHasher(Sha2).HashPassword(User, "password");
        var digest = Convert.ToBase64String(SHA384.HashData(Encoding.UTF8.GetBytes("password")));

        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(User, sha2Hash, digest));
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(User, sha2Hash, "password"));
    }

    [Fact]
    public void VerifyHashedPassword_OnlyUsesTaggedScheme()
    {
        var untaggedSha2 = BCryptExtendedV2.HashPassword("password", 4);
        var sha256Hash = CreateHasher(new PreHashOptions { Scheme = PreHashScheme.Sha2, Digest = HashType.SHA256 }).HashPassword(User, "password");

        // Untagged is plain bcrypt
        Assert.Equal(PasswordVerificationResult.Failed, CreateHasher(Sha2).VerifyHashedPassword(User, untaggedSha2, "password"));
        // Unconfigured scheme
        Assert.Equal(PasswordVerificationResult.Failed, CreateHasher(Sha2, Plain).VerifyHashedPassword(User, sha256Hash, "password"));
        // Unknown or malformed tags
        Assert.Equal(PasswordVerificationResult.Failed, CreateHasher(Sha2).VerifyHashedPassword(User, "$bcnet-sha2-999" + untaggedSha2, "password"));
        Assert.Equal(PasswordVerificationResult.Failed, CreateHasher(Sha2).VerifyHashedPassword(User, "$bcnet-sha2-384", "password"));
    }

    [Fact]
    public void VerifyHashedPassword_AspNetIdentityHash_StillRehashes()
    {
        var identityHasher = new PasswordHasher<TestUser>();
        var identityHash = identityHasher.HashPassword(User, "password");

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, CreateHasher(Hmac()).VerifyHashedPassword(User, identityHash, "password"));
    }

    [Fact]
    public void Misconfiguration_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => CreateHasher(Hmac(key: null)).HashPassword(User, "password"));
        Assert.Throws<InvalidOperationException>(() => CreateHasher(Hmac(key: "")).HashPassword(User, "password"));
        Assert.Throws<InvalidOperationException>(() => CreateHasher(new PreHashOptions { Scheme = PreHashScheme.Sha2, HmacKey = Pepper }).HashPassword(User, "password"));
        Assert.Throws<InvalidOperationException>(() => CreateHasher(new PreHashOptions { Scheme = (PreHashScheme)7 }).HashPassword(User, "password"));
        Assert.Throws<InvalidOperationException>(() => CreateHasher(new PreHashOptions { Scheme = PreHashScheme.Sha2, Digest = HashType.None }).HashPassword(User, "password"));

        // Previous schemes are validated too
        var hash = BCryptNet.BCrypt.HashPassword("password", 4);
        var ex = Assert.Throws<InvalidOperationException>(() => CreateHasher(Plain, Sha2, Hmac(key: null)).VerifyHashedPassword(User, hash, "password"));
        Assert.Contains("PreviousPreHashes[1]", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PreHashOptions_ToStringRedactsKey()
    {
        var text = new BCryptHasherOptions { PreHash = Hmac("super secret") }.ToString();

        Assert.DoesNotContain("super secret", text, StringComparison.Ordinal);
        Assert.Contains("HmacSha3", text, StringComparison.Ordinal);
    }

    [Fact]
    public void UseBcrypt_ValidatesOptions()
    {
        var services = new ServiceCollection();
        services.UseBcrypt<TestUser>(o => o.PreHash = Hmac(key: null));
        using var provider = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<BCryptHasherOptions>>().Value);
        Assert.Contains("HmacKey", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UseBcrypt_RejectsInvalidWorkFactorAtStartup()
    {
        var services = new ServiceCollection();
        services.UseBcrypt<TestUser>(o => o.WorkFactor = 0);
        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<BCryptHasherOptions>>().Value);
    }

    [Fact]
    public void UseBcrypt_BindsFromConfiguration()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["BCrypt:WorkFactor"] = "4",
                ["BCrypt:PreHash:Scheme"] = "HmacSha3",
                ["BCrypt:PreHash:Digest"] = "SHA512",
                ["BCrypt:PreHash:HmacKey"] = Pepper,
                ["BCrypt:PreviousPreHashes:0:Scheme"] = "None",
            })
            .Build();

        var services = new ServiceCollection();
        services.Configure<BCryptHasherOptions>(configuration.GetSection("BCrypt"));
        services.UseBcrypt<TestUser>();
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<TestUser>>();
        using var key = HmacKey.FromString(Pepper);

        var hash = Untag(hasher.HashPassword(User, "password"), "$bcnet-hmac-sha3-512");

        Assert.StartsWith("$2a$04$", hash, StringComparison.Ordinal);
        Assert.True(BCryptExtendedV3.Verify(key, "password", hash, new BCryptOptions(preHash: PreHash.HmacSha3(HashType.SHA512))));
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded,
            hasher.VerifyHashedPassword(User, BCryptNet.BCrypt.HashPassword("password", 4), "password"));
    }
}
