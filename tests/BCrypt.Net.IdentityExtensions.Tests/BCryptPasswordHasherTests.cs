// /*
// The MIT License (MIT)
// Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
// Copyright (c) 2013 Ryan D. Emerle (.Net port)
// Copyright (c) 2016 Chris McKee (.Net-core port / patches / new features)
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
using BCryptNet.IdentityExtensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace BCrypt.Net.IdentityExtensions.Tests;

public sealed class BCryptPasswordHasherTests
{
    private sealed class TestUser;

    [Fact]
    public void HashPassword_Throws_On_Null_Inputs()
    {
        var hasher = new BCryptPasswordHasher<TestUser>(new PasswordHasher<TestUser>());
        var user = new TestUser();

        Assert.Throws<ArgumentNullException>(() => hasher.HashPassword(user, null!));
        Assert.Throws<ArgumentNullException>(() => hasher.HashPassword(null!, "password"));
    }

    [Fact]
    public void HashPassword_Creates_Valid_BCrypt_Hash()
    {
        var hasher = new BCryptPasswordHasher<TestUser>(new PasswordHasher<TestUser>());
        var user = new TestUser();

        var hash = hasher.HashPassword(user, "password");

        Assert.StartsWith("$2", hash, StringComparison.Ordinal);
        Assert.True(BCryptNet.BCrypt.Verify("password", hash));
    }

    [Fact]
    public void VerifyHashedPassword_Uses_AspNetIdentity_Hash_Path()
    {
        var identityHasher = new PasswordHasher<TestUser>();
        var hasher = new BCryptPasswordHasher<TestUser>(identityHasher);
        var user = new TestUser();
        var identityHash = identityHasher.HashPassword(user, "password");

        var result = hasher.VerifyHashedPassword(user, identityHash, "password");
        var failed = hasher.VerifyHashedPassword(user, identityHash, "wrong");

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, result);
        Assert.Equal(PasswordVerificationResult.Failed, failed);
    }

    [Fact]
    public void VerifyHashedPassword_Rehashes_When_WorkFactor_Increases()
    {
        var options = Options.Create(new BCryptHasherOptions { RehashPasswords = true, WorkFactor = 12 });
        var hasher = new BCryptPasswordHasher<TestUser>(new PasswordHasher<TestUser>(), options);
        var user = new TestUser();
        var lowCostHash = BCryptNet.BCrypt.HashPassword("password", 10);
        var highCostHash = BCryptNet.BCrypt.HashPassword("password", 12);

        var rehashNeeded = hasher.VerifyHashedPassword(user, lowCostHash, "password");
        var success = hasher.VerifyHashedPassword(user, highCostHash, "password");

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, rehashNeeded);
        Assert.Equal(PasswordVerificationResult.Success, success);
    }

    [Fact]
    public void VerifyHashedPassword_Returns_Failed_For_Invalid_Password()
    {
        var options = Options.Create(new BCryptHasherOptions { RehashPasswords = false });
        var hasher = new BCryptPasswordHasher<TestUser>(new PasswordHasher<TestUser>(), options);
        var user = new TestUser();
        var hash = BCryptNet.BCrypt.HashPassword("password", 10);

        var result = hasher.VerifyHashedPassword(user, hash, "wrong");

        Assert.Equal(PasswordVerificationResult.Failed, result);
    }
}
