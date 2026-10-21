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
using System.Collections.Concurrent;
using System.Collections.Generic;
using BCryptNet;
using BCryptNet.IdentityExtensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BCrypt.Net.IdentityExtensions.Tests;

public sealed class BCryptPasswordHasherReloadTests : IDisposable
{
    private sealed class TestUser;

    private sealed class CapturingLogger : ILogger<BCryptPasswordHasher<TestUser>>
    {
        public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter) =>
            Entries.Enqueue((logLevel, formatter(state, exception)));
    }

    private static readonly TestUser User = new();

    private readonly IConfigurationRoot _configuration;
    private readonly CapturingLogger _logger = new();
    private readonly ServiceProvider _provider;

    public BCryptPasswordHasherReloadTests()
    {
        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["BCrypt:WorkFactor"] = "4",
                ["BCrypt:PreHash:Scheme"] = "None",
            })
            .Build();

        var services = new ServiceCollection();
        services.Configure<BCryptHasherOptions>(_configuration.GetSection("BCrypt"));
        services.AddSingleton<ILogger<BCryptPasswordHasher<TestUser>>>(_logger);
        services.UseBcrypt<TestUser>();
        _provider = services.BuildServiceProvider();
    }

    public void Dispose() => _provider.Dispose();

    // One scope per call, like one hasher per request
    private IPasswordHasher<TestUser> Hasher()
    {
        using var scope = _provider.CreateScope();
        return scope.ServiceProvider.GetRequiredService<IPasswordHasher<TestUser>>();
    }

    private void Reload(params (string Key, string Value)[] changes) => Assert.Null(TryReload(changes));

    // Invalid reloads throw from Reload(), as the monitor rebuilds options in the change callback
    private Exception TryReload(params (string Key, string Value)[] changes)
    {
        foreach (var (key, value) in changes)
        {
            _configuration[key] = value;
        }

        return Record.Exception(() => _configuration.Reload());
    }

    [Fact]
    public void UseBcrypt_ResolvesLiveOptionsHasher()
    {
        // Proves the IOptionsMonitor constructor is used
        Assert.IsType<BCryptPasswordHasher<TestUser>>(Hasher());
        Assert.StartsWith("$2a$04$", Hasher().HashPassword(User, "password"), StringComparison.Ordinal);

        Reload(("BCrypt:WorkFactor", "5"));

        Assert.StartsWith("$2a$05$", Hasher().HashPassword(User, "password"), StringComparison.Ordinal);
    }

    [Fact]
    public void Reload_ChangesSchemeWithoutRestart()
    {
        var plainHash = Hasher().HashPassword(User, "password");

        Reload(("BCrypt:PreHash:Scheme", "HmacSha3"), ("BCrypt:PreHash:HmacKey", "pepper"),
            ("BCrypt:PreviousPreHashes:0:Scheme", "None"));

        using var key = HmacKey.FromString("pepper");
        var hmacHash = Hasher().HashPassword(User, "password");
        Assert.True(BCryptExtendedV3.Verify(key, "password", BCryptPasswordHasherPreHashTests.Untag(hmacHash, "$bcnet-hmac-sha3-384")));
        Assert.Equal(PasswordVerificationResult.Success, Hasher().VerifyHashedPassword(User, hmacHash, "password"));
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, Hasher().VerifyHashedPassword(User, plainHash, "password"));
    }

    [Fact]
    public void Reload_RotatesHmacKey()
    {
        Reload(("BCrypt:PreHash:Scheme", "HmacSha3"), ("BCrypt:PreHash:HmacKey", "old pepper"));
        var oldHash = Hasher().HashPassword(User, "password");

        Reload(("BCrypt:PreHash:HmacKey", "new pepper"),
            ("BCrypt:PreviousPreHashes:0:Scheme", "HmacSha3"), ("BCrypt:PreviousPreHashes:0:HmacKey", "old pepper"));

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, Hasher().VerifyHashedPassword(User, oldHash, "password"));
        using var newKey = HmacKey.FromString("new pepper");
        Assert.True(BCryptExtendedV3.Verify(newKey, "password",
            BCryptPasswordHasherPreHashTests.Untag(Hasher().HashPassword(User, "password"), "$bcnet-hmac-sha3-384")));
    }

    [Fact]
    public void Reload_InvalidOptions_KeepsLastValidAndLogs()
    {
        Reload(("BCrypt:PreHash:Scheme", "Sha2"));
        var sha2Hash = Hasher().HashPassword(User, "password");

        // No key: fails validation
        var reloadError = Assert.IsType<AggregateException>(TryReload(("BCrypt:PreHash:Scheme", "HmacSha3")));
        Assert.IsType<OptionsValidationException>(reloadError.InnerException);

        Assert.Equal(PasswordVerificationResult.Success, Hasher().VerifyHashedPassword(User, sha2Hash, "password"));
        Assert.True(BCryptExtendedV2.Verify("password",
            BCryptPasswordHasherPreHashTests.Untag(Hasher().HashPassword(User, "password"), "$bcnet-sha2-384")));
        Assert.Single(_logger.Entries, e => e.Level == LogLevel.Error); // once, not per call

        Reload(("BCrypt:PreHash:HmacKey", "pepper"));

        using var key = HmacKey.FromString("pepper");
        Assert.True(BCryptExtendedV3.Verify(key, "password",
            BCryptPasswordHasherPreHashTests.Untag(Hasher().HashPassword(User, "password"), "$bcnet-hmac-sha3-384")));
        Assert.Contains(_logger.Entries, e => e.Level == LogLevel.Information);
    }

    [Fact]
    public void Reload_UnbindableValue_KeepsLastValid()
    {
        Assert.StartsWith("$2a$04$", Hasher().HashPassword(User, "password"), StringComparison.Ordinal);

        Assert.NotNull(TryReload(("BCrypt:PreHash:Scheme", "NotAScheme")));

        Assert.True(BCryptNet.BCrypt.Verify("password", Hasher().HashPassword(User, "password")));
        Assert.Single(_logger.Entries, e => e.Level == LogLevel.Error);
    }

    [Fact]
    public void InvalidOptions_WithNoPreviousValid_Throw()
    {
        Reload(("BCrypt:PreHash:Scheme", "HmacSha3"));

        Assert.Throws<OptionsValidationException>(() => Hasher().HashPassword(User, "password"));
    }
}
