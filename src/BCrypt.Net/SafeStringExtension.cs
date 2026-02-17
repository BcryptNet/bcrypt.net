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
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, salt));
    }

    /// <summary>
    /// Hashes a password using the BCrypt algorithm.
    /// </summary>
    /// <param name="inputKey">The password to be hashed, provided as a <see cref="SecureString"/>.</param>
    /// <param name="workFactor">The computational cost parameter defining the strength of the hash. Defaults to the predefined value of <see cref="BCryptCore.DefaultRounds"/>.</param>
    /// <returns>The hashed password as a string.</returns>
    public static string HashPassword(SecureString inputKey, int workFactor = DefaultRounds)
    {
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, workFactor));
    }

    private static string HashPassword(ReadOnlySpan<char> inputKey, int workFactor = DefaultRounds) =>
        HashPassword(inputKey, GenerateSalt(workFactor));

    private static string HashPassword(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt)
    {
        Span<char> outputBuffer = stackalloc char[60];
        HashPassword(inputKey, salt, outputBuffer, out var outputBufferWritten);
        return new string(outputBuffer[..outputBufferWritten]);
    }

    private static void HashPassword(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, Span<char> outputBuffer, out int outputBufferWritten) => CreatePasswordHash(inputKey, salt, outputBuffer, out outputBufferWritten);

    private delegate string BCryptDelegate(ReadOnlySpan<char> inputKey);

    private static unsafe string GetBCryptHashFromSecureString(SecureString secureString, BCryptDelegate func)
    {
        ArgumentNullException.ThrowIfNull(secureString);
        ArgumentNullException.ThrowIfNull(func);

        int length = secureString.Length;
        if (length == 0)
            throw new ArgumentException("SecureString cannot be empty", nameof(secureString));

        if(!secureString.IsReadOnly())
            secureString.MakeReadOnly();

        IntPtr sourceStringPointer = IntPtr.Zero;

        try
        {
            // Create an unmanaged copy of the secure string.
            sourceStringPointer = Marshal.SecureStringToBSTR(secureString);

            if (sourceStringPointer == IntPtr.Zero)
                throw new InvalidOperationException("Failed to convert SecureString to BSTR");

            // Convert the BSTR pointer directly to ReadOnlySpan<char>
            // Note: This assumes the BSTR is null-terminated & we're working with the actual content
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
