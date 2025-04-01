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

using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace BCryptNet;

public partial class BCryptCore
{
#if NETCOREAPP
    /// <summary>
    /// Create Password Hash Base
    /// </summary>
    /// <param name="inputKey"></param>
    /// <param name="salt"></param>
    /// <param name="hashType"></param>
    /// <param name="enhancedHashKeyGen"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="SaltParseException"></exception>
    internal static string CreatePasswordHash(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, HashType hashType = HashType.None, Func<string, HashType, char, byte[]> enhancedHashKeyGen = null)
    {
        Span<char> outputBuffer = stackalloc char[60];
        CreatePasswordHash(inputKey, salt, outputBuffer, out var outputBufferWritten, hashType, enhancedHashKeyGen);
        return new string(outputBuffer[..outputBufferWritten]);
    }

    /// <summary>
    /// Create Password Hash Base
    /// </summary>
    /// <param name="inputKey"></param>
    /// <param name="salt"></param>
    /// <param name="outputBuffer"></param>
    /// <param name="outputBufferWritten"></param>
    /// <param name="hashType"></param>
    /// <param name="enhancedHashKeyGen"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="SaltParseException"></exception>
    internal static void CreatePasswordHash(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, Span<char> outputBuffer, out int outputBufferWritten, HashType hashType = HashType.None, Func<string, HashType, char, byte[]> enhancedHashKeyGen = null)
    {
        if (salt.IsEmpty)
        {
            throw new ArgumentException("Invalid salt: salt cannot be empty", nameof(salt));
        }

        if (hashType == HashType.None && inputKey.Length > 72)
        {
            throw new ArgumentException("Invalid input key: input key cannot exceed 72 characters for bCrypt", nameof(inputKey));
        }

        if (enhancedHashKeyGen == null && hashType != HashType.None)
        {
            throw new ArgumentException("Invalid HashType, You can't have an enhanced hash without an implementation of the key generator.", nameof(hashType));
        }

        if(outputBuffer.Length != 60)
        {
            throw new ArgumentException("Output buffer must be 60 characters long", nameof(outputBuffer));
        }

        // Determine the starting offset and validate the salt
        int startingOffset;
        char bcryptMinorRevision = (char)0;

        if (salt[0] != '$' || salt[1] != '2')
        {
            throw new SaltParseException("Invalid salt version");
        }

        if (salt[2] == '$')
        {
            startingOffset = 3;
        }
        else
        {
            bcryptMinorRevision = salt[2];
            if (bcryptMinorRevision != 'a' && bcryptMinorRevision != 'b' && bcryptMinorRevision != 'x' &&
                bcryptMinorRevision != 'y' || salt[3] != '$')
            {
                throw new SaltParseException("Invalid salt revision");
            }

            startingOffset = 4;
        }

        // Extract number of rounds
        // Extract details from salt
        if (!int.TryParse(salt.Slice(startingOffset, 2), NumberStyles.None, CultureInfo.InvariantCulture, out int workFactor))
        {
            throw new SaltParseException("Missing salt rounds");
        }

        // Throw if log rounds are out of range on hash, deals with custom salts
        if (workFactor < 1 || workFactor > 31)
        {
            throw new SaltParseException("Salt rounds out of range");
        }

        Span<byte> inputBytes;
        switch (hashType)
        {
            case HashType.None:
                bool appendNul = bcryptMinorRevision >= 'a';
                Span<byte> utf8Buffer = stackalloc byte[Encoding.UTF8.GetMaxByteCount(inputKey.Length + (appendNul ? 1 : 0))];
                int bytesWritten = Encoding.UTF8.GetBytes(inputKey, utf8Buffer);
                if (appendNul) utf8Buffer[bytesWritten++] = 0;
                inputBytes = utf8Buffer[..bytesWritten].ToArray();
                break;
            default:
                if (enhancedHashKeyGen == null)
                {
                    throw new ArgumentException("Invalid HashType, You can't have an enhanced hash without an implementation of the key generator.", nameof(hashType));
                }

                inputBytes = enhancedHashKeyGen(new string(inputKey), hashType, bcryptMinorRevision);
                break;
        }

        if (!HashBytes(inputBytes, salt.Slice(startingOffset + 3, 22), bcryptMinorRevision, workFactor, outputBuffer, out int written))
            throw new BcryptAuthenticationException("Couldn't hash input");

        outputBufferWritten = written;
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="inputBytes"></param>
    /// <param name="extractedSalt"></param>
    /// <param name="bcryptMinorRevision"></param>
    /// <param name="workFactor"></param>
    /// <returns></returns>
    internal static bool HashBytes(
        ReadOnlySpan<byte> inputBytes,
        ReadOnlySpan<char> extractedSalt,
        char bcryptMinorRevision,
        int workFactor,
        Span<char> destination,
        out int charsWritten)
    {
        charsWritten = 0;
        var bCrypt = new BCrypt();

        Span<byte> saltBuffer = stackalloc byte[BCryptSaltLen];
        int written = DecodeBase64(extractedSalt, saltBuffer);
        var saltBytes = saltBuffer[..written];

        Span<byte> hashBuffer = stackalloc byte[BfCryptCiphertext.Length * 4];
        var hashBytes = bCrypt.CryptRaw(inputBytes, saltBytes, workFactor, hashBuffer);

        // Ensure the destination is large enough
        // "$2x$10$" + base64(16 bytes) + base64(23 bytes) = 60 characters
        if (destination.Length < 60)
            return false;

        int pos = 0;
        destination[pos++] = '$';
        destination[pos++] = '2';
        destination[pos++] = bcryptMinorRevision;
        destination[pos++] = '$';

        // Write work factor as 2-digit number
        if (!workFactor.TryFormat(destination.Slice(pos), out int wfChars, "D2"))
            return false;
        pos += wfChars;

        destination[pos++] = '$';

        // Write base64-encoded salt
        if (!TryEncodeBase64(saltBytes, saltBytes.Length, destination.Slice(pos), out int saltChars))
            return false;
        pos += saltChars;

        // Write base64-encoded hash
        if (!TryEncodeBase64(hashBytes, (BfCryptCiphertextLength * 4) - 1, destination.Slice(pos), out int hashChars))
            return false;
        pos += hashChars;

        charsWritten = pos;
        return true;
    }

    internal static string GenerateSalt(int workFactor = DefaultRounds, char bcryptMinorRevision = DefaultHashVersion)
    {
        if (workFactor < MinRounds || workFactor > MaxRounds)
        {
            throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor,
                $"The work factor must be between {MinRounds} and {MaxRounds} (inclusive)");
        }

        if (bcryptMinorRevision != 'a' && bcryptMinorRevision != 'b' && bcryptMinorRevision != 'x' &&
            bcryptMinorRevision != 'y')
        {
            throw new ArgumentException("BCrypt Revision should be a, b, x or y", nameof(bcryptMinorRevision));
        }

        byte[] saltBytes = new byte[BCryptSaltLen];

        RngCsp.GetBytes(saltBytes);

        var result = new StringBuilder(29);
        result.Append('$').Append('2').Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2", CultureInfo.InvariantCulture)).Append('$');

        // Base65 encoded salt
        result.Append(EncodeBase64(saltBytes, saltBytes.Length));

        return result.ToString();
    }

    internal static bool TryEncodeBase64(ReadOnlySpan<byte> byteArray, int length, Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;

        if (length <= 0 || length > byteArray.Length)
            return false;

        int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
        if (destination.Length < encodedSize)
            return false;

        int pos = 0;
        int off = 0;
        while (off < length)
        {
            int c1 = byteArray[off++] & 0xff;
            destination[pos++] = Base64Code[(c1 >> 2) & 0x3f];
            c1 = (c1 & 0x03) << 4;

            if (off >= length)
            {
                destination[pos++] = Base64Code[c1 & 0x3f];
                break;
            }

            int c2 = byteArray[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            destination[pos++] = Base64Code[c1 & 0x3f];
            c1 = (c2 & 0x0f) << 2;

            if (off >= length)
            {
                destination[pos++] = Base64Code[c1 & 0x3f];
                break;
            }

            c2 = byteArray[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            destination[pos++] = Base64Code[c1 & 0x3f];
            destination[pos++] = Base64Code[c2 & 0x3f];
        }

        charsWritten = pos;
        return true;
    }

    internal static Span<char> EncodeBase64(ReadOnlySpan<byte> byteArray, int length)
    {
        if (length <= 0 || length > byteArray.Length)
        {
            throw new ArgumentException("Invalid length", nameof(length));
        }

        int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
        char[] encoded = new char[encodedSize];

        int pos = 0;
        int off = 0;
        while (off < length)
        {
            //Process first byte in group
            int c1 = byteArray[off++] & 0xff;
            encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
            c1 = (c1 & 0x03) << 4;
            if (off >= length)
            {
                encoded[pos++] = Base64Code[c1 & 0x3f];
                break;
            }

            // second byte of group
            int c2 = byteArray[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            encoded[pos++] = Base64Code[c1 & 0x3f];
            c1 = (c2 & 0x0f) << 2;
            if (off >= length)
            {
                encoded[pos++] = Base64Code[c1 & 0x3f];
                break;
            }

            // third byte of group
            c2 = byteArray[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            encoded[pos++] = Base64Code[c1 & 0x3f];
            encoded[pos++] = Base64Code[c2 & 0x3f];
        }

        return encoded;
    }

    /// <summary>
    ///  Decode a string encoded using BCrypt's base64 scheme to a byte array.
    ///  Note that this is *not* compatible with the standard MIME-base64 encoding.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
    ///                                     illegal values.</exception>
    /// <param name="encodedSpan">The string to decode.</param>
    /// <param name="destination"></param>
    /// <returns>The decoded byte array.</returns>
    public static int DecodeBase64(ReadOnlySpan<char> encodedSpan, Span<byte> destination)
    {
        int outputLength = 0;
        int position = 0;

        while (position < encodedSpan.Length - 1 && outputLength < destination.Length)
        {
            int c1 = Char64(encodedSpan[position++]);
            int c2 = Char64(encodedSpan[position++]);
            if (c1 == -1 || c2 == -1) break;

            destination[outputLength] = (byte)((c1 << 2) | ((c2 & 0x30) >> 4));
            if (++outputLength >= destination.Length || position >= encodedSpan.Length) break;

            int c3 = Char64(encodedSpan[position++]);
            if (c3 == -1) break;

            destination[outputLength] = (byte)(((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2));
            if (++outputLength >= destination.Length || position >= encodedSpan.Length) break;

            int c4 = Char64(encodedSpan[position++]);
            if (c4 == -1) break;

            destination[outputLength] = (byte)(((c3 & 0x03) << 6) | c4);
            ++outputLength;
        }

        return outputLength;
    }

    internal ReadOnlySpan<byte> CryptRaw(ReadOnlySpan<byte> inputBytes, ReadOnlySpan<byte> saltBytes, int workFactor, Span<byte> destination)
    {
        int i;
        int j;

        Span<uint> cdata = stackalloc uint[BfCryptCiphertext.Length];
        BfCryptCiphertext.CopyTo(cdata);
        int clen = cdata.Length;

        if (workFactor < MinRounds || workFactor > MaxRounds)
        {
            throw new ArgumentException("Bad number of rounds", nameof(workFactor));
        }

        if (saltBytes.Length != BCryptSaltLen)
        {
            throw new ArgumentException("Bad salt Length", nameof(saltBytes));
        }

        uint rounds = 1u << workFactor;

        // We overflowed rounds at 31 - added safety check
        if (rounds < 1)
        {
            throw new ArgumentException("Bad number of rounds", nameof(workFactor));
        }

        InitializeKey();
        EKSKey(saltBytes, inputBytes);

        for (i = 0; i != rounds; i++)
        {
            Key(inputBytes);
            Key(saltBytes);
        }

        for (i = 0; i < 64; i++)
        {
            for (j = 0; j < (clen >> 1); j++)
            {
                Encipher(cdata, j << 1);
            }
        }

        // Convert ciphertext to output byte-array
        for (i = 0, j = 0; i < clen; i++)
        {
            // per-line extract first byte by shifting cdata word at index right 24 bits
            // using >> op then isolate the least significant byte using mask 0xff
            destination[j++] = (byte)((cdata[i] >> 24) & 0xff);
            destination[j++] = (byte)((cdata[i] >> 16) & 0xff);
            destination[j++] = (byte)((cdata[i] >> 8) & 0xff);
            destination[j++] = (byte)(cdata[i] & 0xff);
        }

        return destination;
    }

#endif
}
