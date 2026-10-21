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

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BCryptNet.IdentityExtensions;

/// <summary>
/// A password hasher that uses BCrypt, optionally pre-hashed with SHA2 (<see cref="BCryptExtendedV2"/>)
/// or HMAC-SHA3 (<see cref="BCryptExtendedV3"/>); see <see cref="BCryptHasherOptions.PreHash"/>.
/// </summary>
/// <remarks>
/// Pre-hashed hashes are tagged with their scheme (e.g. <c>$bcnet-sha2-384$2b$...</c>) and only verify under it.
/// ASP.NET Identity hashes and hashes matching <see cref="BCryptHasherOptions.PreviousPreHashes"/> verify with
/// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>. With an <see cref="IOptionsMonitor{TOptions}"/>, option changes
/// apply without a restart; an invalid reload is logged and the last valid options are kept.
/// </remarks>
/// <typeparam name="TUser"></typeparam>
public class BCryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private readonly PasswordHasher<TUser> _identityHasher;
    private readonly BCryptHasherOptions _options;
    private readonly IOptionsMonitor<BCryptHasherOptions> _optionsMonitor;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a hasher with fixed options.
    /// </summary>
    /// <param name="identityHasher">AspNet Identity PasswordHasher</param>
    /// <param name="optionsAccessor">The options for this instance.</param>
    public BCryptPasswordHasher(PasswordHasher<TUser> identityHasher, IOptions<BCryptHasherOptions> optionsAccessor = null)
    {
        _identityHasher = identityHasher;
        _options = optionsAccessor?.Value ?? new BCryptHasherOptions();
    }

    /// <summary>
    /// Creates a hasher that follows option changes.
    /// </summary>
    /// <param name="identityHasher">AspNet Identity PasswordHasher</param>
    /// <param name="optionsMonitor">The live options.</param>
    /// <param name="logger">Logs invalid reloads.</param>
    public BCryptPasswordHasher(PasswordHasher<TUser> identityHasher, IOptionsMonitor<BCryptHasherOptions> optionsMonitor,
        ILogger<BCryptPasswordHasher<TUser>> logger = null)
    {
        ArgumentNullException.ThrowIfNull(optionsMonitor);
        _identityHasher = identityHasher;
        _optionsMonitor = optionsMonitor;
        _logger = logger;
    }

    // One snapshot per call, so a reload can't mix settings
    private HasherSnapshot Current() => _optionsMonitor is null
        ? new HasherSnapshot(_options, ResolvedPreHashes.For(_options))
        : LiveHasherOptions.Current(_optionsMonitor, _logger);

    /// <summary>
    /// Hashes a password using BCrypt.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public string HashPassword(TUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(user);

        var (settings, schemes) = Current();
        var options = new BCryptOptions(settings.WorkFactor, settings.LongPasswordHandling);
        return SchemeTag.Apply(schemes.Current.PreHash, Hash(password, schemes.Current, options));
    }

    /// <summary>
    /// Verifies that a password matches the hashed password.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="hashedPassword"></param>
    /// <param name="providedPassword"></param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(hashedPassword);
        ArgumentNullException.ThrowIfNull(providedPassword);

        if (hashedPassword.Length == 0)
            return PasswordVerificationResult.Failed;

        // Handle ASP.NET Identity v2 and v3 hashed passwords
        if (CheckForAspIdentityHash(hashedPassword))
        {
            var result = _identityHasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
            if (result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
                return PasswordVerificationResult.SuccessRehashNeeded;

            return PasswordVerificationResult.Failed;
        }

        if (!SchemeTag.TryParse(hashedPassword, out var preHash, out var hash))
            return PasswordVerificationResult.Failed;

        HashInformation hashInfo;
        try
        {
            hashInfo = BCrypt.InterrogateHash(hash);
        }
        catch (HashInformationException)
        {
            // Not a bcrypt hash
            return PasswordVerificationResult.Failed;
        }

        var (settings, schemes) = Current();
        var options = new BCryptOptions(longPasswordHandling: settings.LongPasswordHandling);

        // Only verify under the scheme the hash is tagged with
        if (schemes.Current.PreHash == preHash && Verify(providedPassword, hash, schemes.Current, options))
        {
            return settings.RehashPasswords && hashInfo.WorkFactor < settings.WorkFactor
                ? PasswordVerificationResult.SuccessRehashNeeded
                : PasswordVerificationResult.Success;
        }

        foreach (var previous in schemes.Previous)
        {
            if (previous.PreHash != preHash)
                continue;

            try
            {
                if (Verify(providedPassword, hash, previous, options))
                    return PasswordVerificationResult.SuccessRehashNeeded;
            }
            catch (PasswordTooLongException)
            {
                // An over-long password can't match a plain bcrypt hash
            }
        }

        return PasswordVerificationResult.Failed;
    }

    private static string Hash(string password, ResolvedPreHash scheme, BCryptOptions options) => scheme.PreHash.Scheme switch
    {
        PreHashScheme.None => BCrypt.HashPassword(password, options),
        PreHashScheme.Sha2 => BCryptExtendedV2.HashPassword(password, options.WithPreHash(scheme.PreHash)),
        PreHashScheme.HmacSha3 => BCryptExtendedV3.HashPassword(scheme.HmacKey, password, options.WithPreHash(scheme.PreHash)),
        _ => throw new InvalidOperationException($"Unknown pre-hash scheme {scheme.PreHash}")
    };

    private static bool Verify(string password, string hash, ResolvedPreHash scheme, BCryptOptions options) => scheme.PreHash.Scheme switch
    {
        PreHashScheme.None => BCrypt.Verify(password, hash, options),
        PreHashScheme.Sha2 => BCryptExtendedV2.Verify(password, hash, options.WithPreHash(scheme.PreHash)),
        PreHashScheme.HmacSha3 => BCryptExtendedV3.Verify(scheme.HmacKey, password, hash, options.WithPreHash(scheme.PreHash)),
        _ => throw new InvalidOperationException($"Unknown pre-hash scheme {scheme.PreHash}")
    };

    private static bool CheckForAspIdentityHash(string hash)
    {
        if (hash[0] == '$') return false;
        return hash.FromBase64().ToHex().StartsWith("00", StringComparison.InvariantCulture) || hash.FromBase64().ToHex().StartsWith("01", StringComparison.InvariantCulture);
    }
}
