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

#if NETCOREAPP && SECURESTRING
using System.Runtime.InteropServices;
using System.Security;

namespace BCryptNet;

/// <summary>
/// Provides methods for hashing passwords using the BCrypt algorithm with support
/// for <see cref="SecureString"/> inputs. There are very limited use cases for this class,
/// and it is not recommended for general use as securestring usage in general is discouraged in .net core/.net 5+.
/// </summary>
public sealed class BCryptSafeString : BCryptCore
{
    /// <summary>
    /// Hashes a password using the BCrypt algorithm.
    /// </summary>
    /// <param name="inputKey">The password to be hashed, provided as a <see cref="SecureString"/>.</param>
    /// <param name="salt">A cryptographic salt used for the hashing process.</param>
    /// <returns>The hashed password as a string.</returns>
    public static string HashPassword(SecureString inputKey, string salt)
    {
        return HashPassword(inputKey, salt, LongPasswordHandling.Throw);
    }

    /// <summary>
    /// Hashes a SecureString password with an explicit long-password policy.
    /// </summary>
    /// <param name="inputKey">The password to be hashed.</param>
    /// <param name="salt">A cryptographic salt used for the hashing process.</param>
    /// <param name="longPasswordHandling">Policy for passwords exceeding bcrypt's 72-byte limit.</param>
    /// <returns>The hashed password as a string.</returns>
    public static string HashPassword(SecureString inputKey, string salt, LongPasswordHandling longPasswordHandling)
    {
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, salt.AsSpan(), longPasswordHandling));
    }

    /// <summary>
    /// Hashes a password using the BCrypt algorithm.
    /// </summary>
    /// <param name="inputKey">The password to be hashed, provided as a <see cref="SecureString"/>.</param>
    /// <param name="workFactor">The computational cost parameter defining the strength of the hash. Defaults to the predefined value of <see cref="BCryptCore.DefaultRounds"/>.</param>
    /// <returns>The hashed password as a string.</returns>
    public static string HashPassword(SecureString inputKey, int workFactor = DefaultRounds)
    {
        return HashPassword(inputKey, LongPasswordHandling.Throw, workFactor);
    }

    /// <summary>
    /// Hashes a SecureString password with a generated salt and an explicit long-password policy.
    /// </summary>
    /// <param name="inputKey">The password to be hashed.</param>
    /// <param name="longPasswordHandling">Policy for passwords exceeding bcrypt's 72-byte limit.</param>
    /// <param name="workFactor">The computational cost parameter.</param>
    /// <returns>The hashed password as a string.</returns>
    public static string HashPassword(SecureString inputKey, LongPasswordHandling longPasswordHandling, int workFactor = DefaultRounds)
    {
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, workFactor, longPasswordHandling));
    }

    /// <summary>
    /// Verifies a password against a previously computed BCrypt hash.
    /// </summary>
    /// <param name="inputKey">The candidate password, provided as a <see cref="SecureString"/>.</param>
    /// <param name="hash">The stored BCrypt hash to verify against.</param>
    /// <returns><c>true</c> if the password matches the hash; otherwise <c>false</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="hash"/> is null or empty.</exception>
    /// <exception cref="SaltParseException">Thrown when the stored hash cannot be parsed.</exception>
    public static bool Verify(SecureString inputKey, string hash)
    {
        return Verify(inputKey, hash, LongPasswordHandling.Throw);
    }

    /// <summary>
    /// Verifies a SecureString password using the selected long-password policy.
    /// </summary>
    /// <param name="inputKey">The candidate password.</param>
    /// <param name="hash">The stored BCrypt hash.</param>
    /// <param name="longPasswordHandling">Policy for passwords exceeding bcrypt's 72-byte limit.</param>
    /// <returns><c>true</c> if the password matches; otherwise <c>false</c>.</returns>
    public static bool Verify(SecureString inputKey, string hash, LongPasswordHandling longPasswordHandling)
    {
        if (string.IsNullOrEmpty(hash))
            throw new ArgumentException("Invalid hash", nameof(hash));

        string computed = GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, hash.AsSpan(), longPasswordHandling));

        // bcrypt hashes are at most 60 ASCII characters; encode both sides to bytes for
        // constant-time comparison via the existing SecureEquals implementation.
        Span<byte> hashBytes = stackalloc byte[60];
        Span<byte> computedBytes = stackalloc byte[60];
        int hashLen = SafeUTF8.GetBytes(hash, hashBytes);
        int computedLen = SafeUTF8.GetBytes(computed, computedBytes);
        return SecureEquals(hashBytes[..hashLen], computedBytes[..computedLen]);
    }

    private static string HashPassword(ReadOnlySpan<char> inputKey, int workFactor, LongPasswordHandling longPasswordHandling) =>
        HashPassword(inputKey, GenerateSalt(workFactor), longPasswordHandling);

    private static string HashPassword(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, LongPasswordHandling longPasswordHandling)
    {
        Span<char> outputBuffer = stackalloc char[60];
        HashPassword(inputKey, salt, outputBuffer, out var outputBufferWritten, longPasswordHandling);
        return new string(outputBuffer[..outputBufferWritten]);
    }

    private static void HashPassword(
        ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, Span<char> outputBuffer,
        out int outputBufferWritten, LongPasswordHandling longPasswordHandling) =>
        CreatePasswordHash(inputKey, salt, outputBuffer, out outputBufferWritten,
            longPasswordHandling: longPasswordHandling);

    private delegate string BCryptDelegate(ReadOnlySpan<char> inputKey);

    private static unsafe string GetBCryptHashFromSecureString(SecureString secureString, BCryptDelegate func)
    {
        ArgumentNullException.ThrowIfNull(secureString);
        ArgumentNullException.ThrowIfNull(func);

        int length = secureString.Length;
        if (length == 0)
            throw new ArgumentException("SecureString cannot be empty", nameof(secureString));

        if (!secureString.IsReadOnly())
            secureString.MakeReadOnly();

        IntPtr sourceStringPointer = IntPtr.Zero;

        try
        {
            // Create an unmanaged copy of the secure string.
            sourceStringPointer = Marshal.SecureStringToBSTR(secureString);

            if (sourceStringPointer == IntPtr.Zero)
                throw new InvalidOperationException("Failed to convert SecureString to BSTR");

            // Wrap the BSTR directly in a ReadOnlySpan<char> — no managed string is created, so the
            // password material never touches the GC heap.
            //
            // LIFETIME INVARIANT: inputSpan must not outlive sourceStringPointer. The BSTR is zeroed
            // and freed in the finally block below. The compiler enforces this automatically because
            // ReadOnlySpan<char> is a ref struct: it cannot be stored in a field, boxed, or captured
            // by an async continuation. Do NOT change BCryptDelegate to an async delegate or convert
            // this method to async — doing so would break the invariant without a compile error.
            ReadOnlySpan<char> inputSpan = new ReadOnlySpan<char>(sourceStringPointer.ToPointer(), length);

            return func(inputSpan);
        }
        finally
        {
            // Zero and free the unmanaged string - this is the correct complement to SecureStringToBSTR
            if (sourceStringPointer != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(sourceStringPointer);
            }
        }
    }
}
#endif
