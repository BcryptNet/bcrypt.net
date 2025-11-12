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

#if NETCOREAPP
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace BCryptNet;

public sealed class BCryptSafeString : BCryptCore
{
    public static string HashPassword(SecureString inputKey, string salt)
    {
        return GetBCryptHashFromSecureString(inputKey, key => HashPassword(key, salt));
    }

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
