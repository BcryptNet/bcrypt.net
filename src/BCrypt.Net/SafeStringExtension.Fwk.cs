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

#if PRE_CORE && SECURESTRING
using System.Runtime.InteropServices;
using System.Security;

namespace BCryptNet;

/// <summary>
/// This class provides secure implementations for hashing passwords using the OpenBSD BCrypt algorithm
/// with a focus on allowing sensitive data through <see cref="SecureString"/>.
/// </summary>
/// <remarks>
/// <para>This class extends the core functionality provided by <see cref="BCryptCore"/>.</para>
/// </remarks>
public sealed class BCryptSafeString : BCryptCore
{
    /// <summary>
    ///  Hash a password using the OpenBSD BCrypt scheme with a manually supplied salt/>.
    /// </summary>
    /// <remarks>
    ///  You should generally leave generating salts to the library.
    /// </remarks>
    /// <param name="safeString">The password to hash in a SafeString type.</param>
    /// <param name="salt">The log2 of the number of rounds of hashing to apply - the work
    ///                          factor therefore increases as 2^workFactor. Default is 11</param>
    /// <returns>The hashed password.</returns>
    /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
    public static string HashPassword(SecureString safeString, string salt)
    {
        return GetBCryptHashFromSecureString(safeString, key => HashPassword(key, salt));
    }

    /// <summary>
    /// Hashes a password securely using the OpenBSD BCrypt algorithm.
    /// </summary>
    /// <remarks>
    /// This method takes a <see cref="SecureString"/> and hashes it using the specified work factor.
    /// The function ensures secure handling of the sensitive string in memory.
    /// </remarks>
    /// <param name="inputKey">The password to hash, provided as a <see cref="SecureString"/>.</param>
    /// <param name="workFactor">
    /// The log2 of the number of rounds of hashing to apply, representing the computational cost.
    /// Higher values increase security but require more processing time.
    /// The default value is determined by <see cref="BCryptCore.DefaultRounds"/>.
    /// </param>
    /// <returns>The hashed password as a string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="inputKey"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="inputKey"/> is empty or is not marked as read-only before processing.
    /// </exception>
    public static string HashPassword(SecureString inputKey, int workFactor = DefaultRounds)
    {
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, workFactor));
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
        if (string.IsNullOrEmpty(hash))
            throw new ArgumentException("Invalid hash", nameof(hash));

        string computed = GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, hash));
        return SecureEquals(SafeUTF8.GetBytes(hash), SafeUTF8.GetBytes(computed));
    }

    private static string HashPassword(ReadOnlySpan<char> inputKey, int workFactor = DefaultRounds) =>
        HashPassword(inputKey, GenerateSalt(workFactor));

    private static string HashPassword(ReadOnlySpan<char> inputKey, string salt) =>
        CreatePasswordHash(inputKey, salt.AsSpan());

    private delegate string BCryptDelegate(ReadOnlySpan<char> inputKey);

    private static unsafe string GetBCryptHashFromSecureString(SecureString secureString, BCryptDelegate func)
    {
        if (secureString == null)
            throw new ArgumentNullException(nameof(secureString));
        if (func == null)
            throw new ArgumentNullException(nameof(func));

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

            // Wrap the BSTR directly in a ReadOnlySpan<char> — avoiding a managed string touching the GC heap.
            //
            // LIFETIME INVARIANT: inputSpan must not outlive sourceStringPointer. The BSTR is zeroed
            // and freed in the `finally` block below. The compiler enforces this automatically because
            // ReadOnlySpan<char> is a ref struct: it cannot be stored in a field, boxed, or captured
            // by an async continuation. Do NOT change BCryptDelegate to an async delegate or convert
            // this method to async; breaks the invariant and will error at runtime.
            ReadOnlySpan<char> inputSpan = new ReadOnlySpan<char>(sourceStringPointer.ToPointer(), length);

            return func(inputSpan);
        }
        finally
        {
            // Zero and free the unmanaged string - this is the correct complement to SecureStringToBSTR https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-security-securestring#securestring-and-interop
            if (sourceStringPointer != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(sourceStringPointer);
            }
        }
    }
}

#endif
