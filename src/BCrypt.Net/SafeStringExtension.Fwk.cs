// /*
// The MIT License (MIT)
// Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
// Copyright (c) 2013 Ryan D. Emerle (.Net port)
// Copyright (c) 2016/2025 Chris McKee (.Net-core port / patches / new features)
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

#if !NETCOREAPP
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace BCryptNet;

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

    public static string HashPassword(SecureString inputKey, int workFactor = DefaultRounds)
    {
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, workFactor));
    }

    private static string HashPassword(string inputKey, int workFactor = DefaultRounds) =>
        HashPassword(inputKey, GenerateSalt(workFactor));

    private static string HashPassword(string inputKey, string salt)
    {
        return CreatePasswordHash(inputKey, salt);
    }

    private delegate string SandboxedSecureString(string inputKey);

    private static unsafe string GetBCryptHashFromSecureString(SecureString secureString, SandboxedSecureString func)
    {
        if (secureString == null)
            throw new ArgumentNullException(nameof(secureString));
        if (func == null)
            throw new ArgumentNullException(nameof(func));

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

            // Convert BSTR pointer to a managed string
            // Note: We need to use Marshal.PtrToStringUni for wide character strings
            string inputKey = Marshal.PtrToStringUni(sourceStringPointer);

            if (inputKey == null)
                throw new InvalidOperationException("Failed to convert BSTR to string");

            return func(inputKey);
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
