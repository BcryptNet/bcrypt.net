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

namespace BCryptNet;

/// <summary>BCrypt implementation.</summary>
/// <remarks>
///  <para>
///        BCrypt implements OpenBSD-style Blowfish password hashing using the scheme described in
///        <a href="http://www.usenix.org/event/usenix99/provos/provos_html/index.html">
///        A Future-Adaptable Password Scheme</a> by Niels Provos and David Mazieres.
///  </para>
///  <para>
///        This password hashing system tries to thwart off-line password cracking using a
///        computationally intensive hashing algorithm, based on Bruce Schneier's Blowfish cipher.
///        The work factor of the algorithm is parameterised, so it can be increased as computers
///        get faster.
///  </para>
///  <para>
///        To hash a password using the defaults, call the <see cref="BCrypt.HashPassword(string,int)"/> (which will generate a random salt and hash at default cost), like this:
///  </para>
///  <code>string pw_hash = BCrypt.HashPassword(plain_password);</code>
///  <para>
///         To hash a password using SHA384 pre-hashing for increased entropy see the <see cref="BCryptExtendedV2"/> class
///  </para>
///  <para>
///        To check whether a plaintext password matches one that has been hashed previously,
///        use the <see cref="BCrypt.Verify(string, string, BCryptOptions)"/> method:
/// </para>
///  <code>
///     if (BCrypt.Verify(candidate_password, stored_hash))
///         Console.WriteLine("It matches");
///     else
///         Console.WriteLine("It does not match");
///   </code>
///   <para>
///         The <see cref="BCryptCore.GenerateSalt"/> method takes an optional parameter (workFactor) that
///         determines the computational complexity of the hashing:
///   </para>
///   <code>
///     string strong_salt = BCrypt.GenerateSalt(10);
///     string stronger_salt = BCrypt.GenerateSalt(12);
///   </code>
///   <para>
///         The amount of work increases exponentially (2^workFactor), so each increment is twice
///         as much work. The default workFactor is 10, and the valid range is 4 to 31.
///   </para>
/// </remarks>
public sealed class BCrypt : BCryptCore
{
    /// <summary>
    /// Validate existing hash and password
    /// If valid returns a new hash with the set work-factor
    /// or simply a new hash (salt replaced)
    /// </summary>
    /// <param name="currentKey">Current password / string</param>
    /// <param name="currentHash">Current hash to validate password against</param>
    /// <param name="newKey">New password</param>
    /// <param name="options">Hashing options: <see cref="BCryptOptions.WorkFactor"/> sets the cost of the new hash (raised to match the current hash unless <paramref name="forceWorkFactor"/> is set), and <see cref="BCryptOptions.LongPasswordHandling"/> is applied when verifying the current password and hashing the new one. <see cref="BCryptOptions.PreHash"/> is not supported by plain bcrypt and must be <c>null</c> or <see cref="BCryptNet.PreHash.None"/>.</param>
    /// <param name="forceWorkFactor">By default, this method will not accept a work factor lower
    /// than the one set in the current hash and will set the new work-factor to match.</param>
    /// <exception cref="BcryptAuthenticationException">returned if the users hash and current pass doesn't validate</exception>
    /// <exception cref="SaltParseException">returned if the salt is invalid in any way</exception>
    /// <exception cref="ArgumentException">returned if the hash is invalid</exception>
    /// <exception cref="ArgumentNullException">returned if the user hash is null</exception>
    /// <returns>New hash of new password</returns>
    public static string ValidateAndUpgradeHash(
        string currentKey, string currentHash, string newKey, BCryptOptions options = default, bool forceWorkFactor = false)
    {
        HashContext context = HashContext.ForBCrypt(options);
        return UpgradeHash(currentKey, currentHash, in context, newKey, in context, options.WorkFactor, forceWorkFactor);
    }

    /// <summary>
    /// Validate an existing hash created with any pre-hash scheme and, if valid, return a new hash of
    /// <paramref name="newKey"/> using the scheme in <paramref name="options"/>. Use this to move between schemes
    /// (e.g. plain bcrypt or <see cref="BCryptExtendedV2"/> to HMAC-SHA3) or to rotate an HMAC key.
    /// </summary>
    /// <remarks>
    /// Bcrypt hashes don't record their pre-hash scheme, so <paramref name="currentPreHash"/> must say how
    /// <paramref name="currentHash"/> was created.
    /// </remarks>
    /// <param name="currentKey">Current password.</param>
    /// <param name="currentHash">Current hash to validate the password against.</param>
    /// <param name="currentPreHash">Pre-hash scheme <paramref name="currentHash"/> was created with.</param>
    /// <param name="newKey">New password.</param>
    /// <param name="options">Options for the new hash: <see cref="BCryptOptions.PreHash"/> is the target scheme (<c>null</c> means plain bcrypt);
    /// <see cref="BCryptOptions.WorkFactor"/> sets its cost (raised to match the current hash unless <paramref name="forceWorkFactor"/> is set).
    /// <see cref="BCryptOptions.LongPasswordHandling"/> applies to whichever side is plain bcrypt, and must match the policy the current hash was created with.</param>
    /// <param name="currentHmacKey">HMAC key for <paramref name="currentPreHash"/>; required for <see cref="PreHashScheme.HmacSha3"/>, otherwise must be <c>null</c>.</param>
    /// <param name="newHmacKey">HMAC key for the new hash; required when the target scheme is <see cref="PreHashScheme.HmacSha3"/>, otherwise must be <c>null</c>.
    /// May differ from <paramref name="currentHmacKey"/> to rotate keys.</param>
    /// <param name="forceWorkFactor">By default, this method will not accept a work factor lower
    /// than the one set in the current hash and will set the new work-factor to match.</param>
    /// <exception cref="BcryptAuthenticationException">returned if the users hash and current pass doesn't validate</exception>
    /// <exception cref="SaltParseException">returned if the salt is invalid in any way</exception>
    /// <exception cref="ArgumentException">returned if the hash is invalid, or an HMAC key is supplied to a scheme that doesn't use one</exception>
    /// <exception cref="ArgumentNullException">returned if a password, or an HMAC key a scheme requires, is null</exception>
    /// <exception cref="PlatformNotSupportedException">returned if either scheme isn't supported on this platform (see <see cref="PreHash.IsSupported"/>)</exception>
    /// <returns>New hash of new password</returns>
    public static string ValidateAndUpgradeHash(
        string currentKey,
        string currentHash,
        PreHash currentPreHash,
        string newKey,
        BCryptOptions options = default,
        HmacKey currentHmacKey = null,
        HmacKey newHmacKey = null,
        bool forceWorkFactor = false)
    {
        // Validate both schemes and keys before checking credentials
        HashContext newContext = HashContext.Create(options.ResolvePreHash(PreHash.None), options.LongPasswordHandling, newHmacKey, nameof(newHmacKey));
        HashContext currentContext = HashContext.Create(currentPreHash, options.LongPasswordHandling, currentHmacKey, nameof(currentHmacKey));
        return UpgradeHash(currentKey, currentHash, in currentContext, newKey, in newContext, options.WorkFactor, forceWorkFactor);
    }

    /// <summary>
    ///  Verifies that the hash of the given <paramref name="text"/> matches the provided
    ///  <paramref name="hash"/>
    /// </summary>
    /// <param name="text">The text to verify.</param>
    /// <param name="hash"> The previously hashed password.</param>
    /// <param name="options">Hashing options used to recompute the hash: <see cref="BCryptOptions.LongPasswordHandling"/> must match the policy used when the hash was created; <see cref="BCryptOptions.WorkFactor"/> is ignored as it is read from the hash. <see cref="BCryptOptions.PreHash"/> is not supported by plain bcrypt and must be <c>null</c> or <see cref="BCryptNet.PreHash.None"/>.</param>
    /// <returns>true if the passwords match, false otherwise.</returns>
    /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values.</exception>
    /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
    public static bool Verify(string text, string hash, BCryptOptions options = default)
    {
#if NETCOREAPP
        return Verify(text.AsSpan(), hash.AsSpan(), options);
#else
        return SecureEquals(SafeUTF8.GetBytes(hash), SafeUTF8.GetBytes(CreatePasswordHash(text.AsSpan(), hash.AsSpan(), HashContext.ForBCrypt(options))));
#endif
    }

    /// <summary>
    ///  Hash a password using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCryptCore.GenerateSalt"/> using the given <paramref name="workFactor"/>.
    /// </summary>
    /// <param name="inputKey">The password to hash.</param>
    /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
    ///                          factor therefore increases as 2^workFactor. Default is 11</param>
    /// <returns>The hashed password.</returns>
    /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
    public static string HashPassword(string inputKey, int workFactor = DefaultRounds) =>
        HashPassword(inputKey, GenerateSalt(workFactor));

    /// <summary>
    ///  Hash a password using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCryptCore.GenerateSalt"/> using the given <paramref name="options"/>.
    /// </summary>
    /// <param name="inputKey">The password to hash.</param>
    /// <param name="options">Hashing options: <see cref="BCryptOptions.WorkFactor"/> sets the cost of the generated salt and <see cref="BCryptOptions.LongPasswordHandling"/> controls passwords exceeding the 72-byte bcrypt limit. <see cref="BCryptOptions.PreHash"/> is not supported by plain bcrypt and must be <c>null</c> or <see cref="BCryptNet.PreHash.None"/>.</param>
    /// <returns>The hashed password.</returns>
    /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
    public static string HashPassword(string inputKey, BCryptOptions options) =>
        HashPassword(inputKey, GenerateSalt(options.WorkFactor), options);

    /// <summary>
    ///  Hash a password using the OpenBSD BCrypt scheme with a manually supplied salt/>.
    /// </summary>
    /// <remarks>
    ///  You should generally leave generating salts to the library.
    /// </remarks>
    /// <param name="inputKey">The password to hash.</param>
    /// <param name="salt">the salt to hash with (best generated using <see cref="BCryptCore.GenerateSalt(int,char)"/>); its work factor is used and <see cref="BCryptOptions.WorkFactor"/> is ignored.</param>
    /// <param name="options">Hashing options: <see cref="BCryptOptions.LongPasswordHandling"/> controls passwords exceeding the 72-byte bcrypt limit; <see cref="BCryptOptions.WorkFactor"/> is ignored as the salt carries its own. <see cref="BCryptOptions.PreHash"/> is not supported by plain bcrypt and must be <c>null</c> or <see cref="BCryptNet.PreHash.None"/>.</param>
    /// <returns>The hashed password.</returns>
    /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
    public static string HashPassword(string inputKey, string salt, BCryptOptions options = default)
    {
#if NETCOREAPP
        return HashPassword(inputKey.AsSpan(), salt.AsSpan(), options);
#else
        return CreatePasswordHash(inputKey.AsSpan(), salt.AsSpan(), HashContext.ForBCrypt(options));
#endif
    }

#if PRE_CORE
    /// <inheritdoc cref="HashPassword(string, string, BCryptOptions)"/>
    public static string HashPassword(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, BCryptOptions options = default)
    {
        return CreatePasswordHash(inputKey, salt, HashContext.ForBCrypt(options));
    }
#endif

#if NETCOREAPP
        /// <inheritdoc cref="HashPassword(string, string, BCryptOptions)"/>
        public static string HashPassword(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, BCryptOptions options = default)
        {
            Span<char> outputBuffer = stackalloc char[60];
            HashPassword(inputKey, salt, outputBuffer, out var outputBufferWritten, options);
            return new string(outputBuffer[..outputBufferWritten]);
        }

        /// <summary>
        ///  Hash a password using the OpenBSD BCrypt scheme with a manually supplied salt into a caller-provided buffer.
        /// </summary>
        /// <remarks>
        ///  You should generally leave generating salts to the library.
        /// </remarks>
        /// <param name="inputKey">The password to hash.</param>
        /// <param name="salt">The salt to hash with; its work factor is used and <see cref="BCryptOptions.WorkFactor"/> is ignored.</param>
        /// <param name="outputBuffer">Buffer for the resulting hash; must be 60 characters.</param>
        /// <param name="outputBufferWritten">Number of characters written.</param>
        /// <param name="options">Hashing options: <see cref="BCryptOptions.LongPasswordHandling"/> controls passwords exceeding the 72-byte bcrypt limit; <see cref="BCryptOptions.WorkFactor"/> is ignored as the salt carries its own. <see cref="BCryptOptions.PreHash"/> is not supported by plain bcrypt and must be <c>null</c> or <see cref="BCryptNet.PreHash.None"/>.</param>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static void HashPassword(
            ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, Span<char> outputBuffer,
            out int outputBufferWritten, BCryptOptions options = default) =>
            CreatePasswordHash(inputKey, salt, outputBuffer, out outputBufferWritten, HashContext.ForBCrypt(options));

        /// <inheritdoc cref="Verify(string, string, BCryptOptions)"/>
        public static bool Verify(ReadOnlySpan<char> text, ReadOnlySpan<char> hash, BCryptOptions options = default) =>
            VerifyHash(text, hash, HashContext.ForBCrypt(options));
#endif

    /// <summary>
    /// Returns true if the work factor (logrounds) set on the hash is lower than the new minimum workload passed in
    /// </summary>
    /// <param name="hash">full bcrypt hash</param>
    /// <param name="newMinimumWorkLoad">target workload</param>
    /// <returns>true if new work factor is higher than the one in the hash</returns>
    /// <exception cref="ArgumentException">throws if the current hash workload (logrounds) can not be parsed</exception>
    /// <exception cref="HashInformationException"></exception>
    public static bool PasswordNeedsRehash(string hash, int newMinimumWorkLoad) =>
        HashParser.GetWorkFactor(hash) < newMinimumWorkLoad;

    /// <summary>
    /// Takes a valid hash and outputs its component parts
    /// </summary>
    /// <param name="hash"></param>
    /// <exception cref="HashInformationException"></exception>
    public static HashInformation InterrogateHash(string hash)
    {
        try
        {
            return HashParser.GetHashInformation(hash);
        }
        catch (Exception ex)
        {
            throw new HashInformationException("Error handling string interrogation", ex);
        }
    }
}
