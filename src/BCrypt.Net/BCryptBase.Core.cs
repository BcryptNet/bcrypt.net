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

#if NETCOREAPP
using System.Globalization;
using System.Runtime.CompilerServices;

namespace BCryptNet;

/// <summary>
/// .Net 5+ implementation
/// </summary>
public partial class BCryptCore
{
    // Inputs whose UTF-8 encoding fits in this many bytes are encoded on the stack; larger ones use a pooled
    // array. Either way the buffer is zeroed before it is released.
    internal const int StackallocByteThreshold = 256;

    /// <summary>
    /// Create Password Hash Base
    /// </summary>
    /// <param name="inputKey"></param>
    /// <param name="salt"></param>
    /// <param name="context">Long-password policy and pre-hash settings</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="SaltParseException"></exception>
    internal static string CreatePasswordHash(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt, in HashContext context)
    {
        Span<char> outputBuffer = stackalloc char[60];
        CreatePasswordHash(inputKey, salt, outputBuffer, out var outputBufferWritten, in context);
        return new string(outputBuffer[..outputBufferWritten]);
    }

    /// <summary>
    /// Create Password Hash Base
    /// </summary>
    /// <param name="inputKey"></param>
    /// <param name="salt"></param>
    /// <param name="outputBuffer"></param>
    /// <param name="outputBufferWritten"></param>
    /// <param name="context">Long-password policy and pre-hash settings</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="SaltParseException"></exception>
    internal static void CreatePasswordHash(ReadOnlySpan<char> inputKey, ReadOnlySpan<char> salt,
        Span<char> outputBuffer, out int outputBufferWritten, in HashContext context)
    {
        LongPasswordHandling longPasswordHandling = context.LongPasswordHandling;
        HashType hashType = context.HashType;

        ValidateLongPasswordHandling(longPasswordHandling);

        if (salt.IsEmpty)
        {
            throw new ArgumentException("Invalid salt: salt cannot be empty", nameof(salt));
        }

        if (context.Kind == PreHashKind.None && hashType != HashType.None)
        {
            throw new ArgumentException("Invalid HashType, You can't have an enhanced hash without an implementation of the key generator.", nameof(context));
        }

        if (outputBuffer.Length != 60)
        {
            throw new ArgumentException("Output buffer must be 60 characters long", nameof(outputBuffer));
        }

        // Determine the starting offset and validate the salt
        int startingOffset;
        char bcryptMinorRevision = (char)0;

        if (salt.Length < 3 || salt[0] != '$' || salt[1] != '2')
        {
            throw new SaltParseException("Invalid salt version");
        }

        if (salt[2] == '$')
        {
            startingOffset = 3;
        }
        else
        {
            if (salt.Length < 4)
            {
                throw new SaltParseException("Invalid salt revision");
            }

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
        if (salt.Length <= startingOffset + 2 || salt[startingOffset + 2] != '$')
        {
            throw new SaltParseException("Missing salt rounds");
        }

        if (!int.TryParse(salt.Slice(startingOffset, 2), NumberStyles.None, CultureInfo.InvariantCulture, out int workFactor))
        {
            throw new SaltParseException("Missing salt rounds");
        }

        // Throw if log rounds are out of range on hash, deals with custom salts
        if (workFactor < MinRounds || workFactor > MaxRounds)
        {
            throw new SaltParseException("Salt rounds out of range");
        }

        switch (hashType)
        {
            case HashType.None:
                bool appendNul = bcryptMinorRevision >= 'a';
                if (longPasswordHandling == LongPasswordHandling.Truncate)
                {
                    inputKey = TrimForTruncation(inputKey);
                }
                int inputByteCount = SafeUTF8.GetByteCount(inputKey) + (appendNul ? 1 : 0);
                if (longPasswordHandling == LongPasswordHandling.Throw && inputByteCount > 72)
                {
                    throw new PasswordTooLongException("Invalid input key: input key cannot exceed 72 bytes for bCrypt");
                }
                Span<byte> utf8Buffer = stackalloc byte[SafeUTF8.GetMaxByteCount(inputKey.Length + (appendNul ? 1 : 0))];
                try
                {
                    if (salt.Length < startingOffset + 25)
                    {
                        throw new SaltParseException("Invalid salt");
                    }

                    int bytesWritten = SafeUTF8.GetBytes(inputKey, utf8Buffer);
                    if (appendNul) utf8Buffer[bytesWritten++] = 0;
                    if (longPasswordHandling == LongPasswordHandling.Truncate && bytesWritten > 72)
                    {
                        bytesWritten = 72;
                    }
                    Span<byte> inputBytes = utf8Buffer[..bytesWritten];
                    if (!HashBytes(inputBytes, salt.Slice(startingOffset + 3, 22), bcryptMinorRevision, workFactor, outputBuffer, out int hashBytesWritten))
                        throw new BcryptAuthenticationException("Couldn't hash input");
                    outputBufferWritten = hashBytesWritten;
                }
                finally
                {
                    ZeroMemory(utf8Buffer);
                }

                return;

            default:
                Span<byte> eInputBuffer = stackalloc byte[128];

                try
                {
                    if (salt.Length < startingOffset + 25)
                    {
                        throw new SaltParseException("Invalid salt");
                    }

                    int eInputLen = context.Kind switch
                    {
                        PreHashKind.Sha2 => BCryptExtendedV2.EnhancedHash(inputKey, hashType, bcryptMinorRevision, eInputBuffer),
                        PreHashKind.HmacSha3 => BCryptExtendedV3.EnhancedHash(context.HmacKey, inputKey, hashType, eInputBuffer, bcryptMinorRevision),
                        _ => throw new ArgumentException("Invalid HashType, You can't have an enhanced hash without an implementation of the key generator.", nameof(context))
                    };
                    Span<byte> eInputBytes = eInputBuffer[..eInputLen];
                    if (!HashBytes(eInputBytes, salt.Slice(startingOffset + 3, 22), bcryptMinorRevision, workFactor, outputBuffer, out int written))
                        throw new BcryptAuthenticationException("Couldn't hash input");
                    outputBufferWritten = written;
                }
                finally
                {
                    ZeroMemory(eInputBuffer);
                }

                return;
        }
    }

    /// <summary>
    /// Hashes <paramref name="text"/> with the salt from <paramref name="hash"/> and compares the result in constant time.
    /// </summary>
    internal static bool VerifyHash(ReadOnlySpan<char> text, ReadOnlySpan<char> hash, in HashContext context)
    {
        if (SafeUTF8.GetByteCount(hash) > 60)
        {
            return false;
        }

        Span<byte> hashBytes = stackalloc byte[60];
        int hashLen = SafeUTF8.GetBytes(hash, hashBytes);

        Span<char> computedHash = stackalloc char[60];
        CreatePasswordHash(text, hash, computedHash, out int computedHashLen, in context);

        Span<byte> computedBytes = stackalloc byte[60];
        int computedLen = SafeUTF8.GetBytes(computedHash[..computedHashLen], computedBytes);

        return SecureEquals(hashBytes[..hashLen], computedBytes[..computedLen]);
    }

    /// <summary>
    /// Writes the pre-hash key material bcrypt consumes: base64(<paramref name="digest"/>) as ASCII bytes,
    /// NUL-terminated for revisions 'a' and later.
    /// </summary>
    internal static int EncodePreHash(ReadOnlySpan<byte> digest, char bcryptMinorRevision, Span<byte> destination)
    {
        Span<char> base64Chars = stackalloc char[88]; // base64 of a 64-byte (SHA-512) digest
        try
        {
            if (!Convert.TryToBase64Chars(digest, base64Chars, out int base64Len))
                throw new BcryptAuthenticationException("Base64 encoding failed in EnhancedHash");

            // base64 is ASCII, so each char is exactly one UTF-8 byte
            for (int i = 0; i < base64Len; i++)
            {
                destination[i] = (byte)base64Chars[i];
            }

            if (bcryptMinorRevision >= 'a')
            {
                destination[base64Len++] = 0;
            }

            return base64Len;
        }
        finally
        {
            ZeroMemory(base64Chars);
        }
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="inputBytes"></param>
    /// <param name="extractedSalt"></param>
    /// <param name="bcryptMinorRevision"></param>
    /// <param name="workFactor"></param>
    /// <param name="destination"></param>
    /// <param name="charsWritten"></param>
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
        Span<byte> hashBuffer = stackalloc byte[BfCryptCiphertext.Length * 4];

        try
        {
            int written = DecodeBase64(extractedSalt, saltBuffer);
            if (written != BCryptSaltLen)
                throw new SaltParseException("Invalid salt");

            var saltBytes = saltBuffer[..written];

            var hashBytes = bCrypt.CryptRaw(inputBytes, saltBytes, workFactor, hashBuffer);

            // Ensure the destination is large enough
            // "$2x$10$" + base64(16 bytes) + base64(23 bytes) = 60 characters
            if (destination.Length < 60)
                return false;

            int pos = 0;
            destination[pos++] = '$';
            destination[pos++] = '2';
            // Legacy "$2$" hashes have no revision letter
            if (bcryptMinorRevision >= 'a')
                destination[pos++] = bcryptMinorRevision;
            destination[pos++] = '$';

            // Write work factor as 2-digit number
            if (!workFactor.TryFormat(destination[pos..], out int wfChars, "D2", CultureInfo.InvariantCulture))
                return false;
            pos += wfChars;

            destination[pos++] = '$';

            // Write base64-encoded salt
            pos += EncodeBase64(saltBytes, saltBytes.Length, destination[pos..]);

            // Write base64-encoded hash
            pos += EncodeBase64(hashBytes, (BfCryptCiphertextLength * 4) - 1, destination[pos..]);

            charsWritten = pos;

            return true;
        }
        finally
        {
            ZeroMemory(hashBuffer);
            ZeroMemory(saltBuffer);
        }
    }

    internal static ReadOnlySpan<char> GenerateSalt(int workFactor = DefaultRounds, char bcryptMinorRevision = DefaultHashVersion)
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

        Span<byte> saltBytes = stackalloc byte[BCryptSaltLen];

        RngCsp.GetBytes(saltBytes);

        Span<char> result = stackalloc char[29]; // Adjust the length as needed
        result[0] = '$';
        result[1] = '2';
        result[2] = bcryptMinorRevision;
        result[3] = '$';
        workFactor.TryFormat(result.Slice(4, 2), out _, "D2", CultureInfo.InvariantCulture);
        result[6] = '$';
        EncodeBase64(saltBytes, saltBytes.Length, result[7..]);

        return result.ToArray();
    }

    internal static int EncodeBase64(ReadOnlySpan<byte> byteArray, int length, Span<char> destination)
    {
        if (length <= 0 || length > byteArray.Length)
        {
            throw new ArgumentException("Invalid length", nameof(length));
        }

        int pos = 0;
        int off = 0;
        while (off < length)
        {
            //Process the first byte in the group
            int c1 = byteArray[off++] & 0xff;
            destination[pos++] = Base64Code[(c1 >> 2) & 0x3f];
            c1 = (c1 & 0x03) << 4;
            if (off >= length)
            {
                destination[pos++] = Base64Code[c1 & 0x3f];
                break;
            }

            // second byte of the group
            int c2 = byteArray[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            destination[pos++] = Base64Code[c1 & 0x3f];
            c1 = (c2 & 0x0f) << 2;
            if (off >= length)
            {
                destination[pos++] = Base64Code[c1 & 0x3f];
                break;
            }

            // third byte of the group
            c2 = byteArray[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            destination[pos++] = Base64Code[c1 & 0x3f];
            destination[pos++] = Base64Code[c2 & 0x3f];
        }

        return pos;
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
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int DecodeBase64(ReadOnlySpan<char> encodedSpan, Span<byte> destination)
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

        inputBytes = KeyOrNul(inputBytes);

        InitializeKey();
        try
        {
            EKSKey(saltBytes, inputBytes);

            for (uint ix = 0; ix != rounds; ix++)
            {
                Key(inputBytes);
                Key(saltBytes);
            }

            int i, j;
            for (i = 0; i < 64; i++)
            {
                for (j = 0; j < (clen >> 1); j++)
                {
                    Encipher(cdata, j << 1);
                }
            }

            // Convert ciphertext to an output byte-array
            for (i = 0, j = 0; i < clen; i++)
            {
                // per-line extract the first byte by shifting cdata word at index right 24 bits
                // using >> op then isolate the least significant byte using mask 0xff
                destination[j++] = (byte)((cdata[i] >> 24) & 0xff);
                destination[j++] = (byte)((cdata[i] >> 16) & 0xff);
                destination[j++] = (byte)((cdata[i] >> 8) & 0xff);
                destination[j++] = (byte)(cdata[i] & 0xff);
            }

            return destination;
        }
        finally
        {
            ZeroMemory(_p);
            ZeroMemory(_s);
        }
    }

    /// <summary>Blowfish encipher a single 64-bit block encoded as two 32-bit halves.</summary>
    /// <param name="blockArray">An array containing the two 32-bit half-blocks. The plaintext to be encrypted</param>
    /// <param name="offset">    The position in the array of the blocks.</param>
    private void Encipher(Span<uint> blockArray, int offset)
    {
        uint block = blockArray[offset];
        uint r = blockArray[offset + 1];

        block ^= _p[0];

        unchecked
        {
            uint round;
            for (round = 0; round <= BlowfishNumRounds - 2;)
            {
                // Feistel substitution on the left word
                uint n = _s[(block >> 24) & 0xff];
                n += _s[0x100 | ((block >> 16) & 0xff)];
                n ^= _s[0x200 | ((block >> 8) & 0xff)];
                n += _s[0x300 | (block & 0xff)];
                r ^= n ^ _p[++round];

                // Feistel substitution on the right word
                n = _s[(r >> 24) & 0xff];
                n += _s[0x100 | ((r >> 16) & 0xff)];
                n ^= _s[0x200 | ((r >> 8) & 0xff)];
                n += _s[0x300 | (r & 0xff)];
                block ^= n ^ _p[++round];
            }

            blockArray[offset] = r ^ _p[BlowfishNumRounds + 1];
            blockArray[offset + 1] = block;
        }
    }

    /// <summary>Cyclically extract a word of key material.</summary>
    /// <param name="data">The string to extract the data from.</param>
    /// <param name="offset"> [in, out] The current offset.</param>
    /// <returns>The next word of material from data.</returns>
    private static uint StreamToWord(ReadOnlySpan<byte> data, ref int offset)
    {
        int i;
        uint word = 0;

        for (i = 0; i < 4; i++)
        {
            word = (word << 8) | (uint)(data[offset] & 0xff);
            offset = (offset + 1) % data.Length;
        }

        return word;
    }

    /// <summary>Key the Blowfish cipher.</summary>
    /// <param name="keyBytes">The key byte array.</param>
    private void Key(ReadOnlySpan<byte> keyBytes)
    {
        int i;
        int kOfP = 0;
        Span<uint> lr = stackalloc uint[2] { 0, 0 };

        int pLen = _p.Length, sLen = _s.Length;

        for (i = 0; i < pLen; i++)
        {
            _p[i] = _p[i] ^ StreamToWord(keyBytes, ref kOfP);
        }

        for (i = 0; i < pLen; i += 2)
        {
            Encipher(lr, 0);
            _p[i] = lr[0];
            _p[i + 1] = lr[1];
        }

        for (i = 0; i < sLen; i += 2)
        {
            Encipher(lr, 0);
            _s[i] = lr[0];
            _s[i + 1] = lr[1];
        }
    }

    /// <summary>
    ///  Perform the "enhanced key schedule" step described by Provos and Mazieres in
    ///  "A Future Adaptable Password Scheme" http://www.openbsd.org/papers/bcrypt-paper.ps.
    /// </summary>
    /// <param name="saltBytes"> Salt byte array.</param>
    /// <param name="inputBytes">Input byte array.</param>
    // ReSharper disable once InconsistentNaming
    private void EKSKey(ReadOnlySpan<byte> saltBytes, ReadOnlySpan<byte> inputBytes)
    {
        int i;
        int passwordOffset = 0;
        int saltOffset = 0;

        Span<uint> lr = stackalloc uint[2] { 0, 0 };

        int pLen = _p.Length, sLen = _s.Length;

        for (i = 0; i < pLen; i++)
        {
            _p[i] = _p[i] ^ StreamToWord(inputBytes, ref passwordOffset);
        }

        for (i = 0; i < pLen; i += 2)
        {
            lr[0] ^= StreamToWord(saltBytes, ref saltOffset);
            lr[1] ^= StreamToWord(saltBytes, ref saltOffset);
            Encipher(lr, 0);
            _p[i] = lr[0];
            _p[i + 1] = lr[1];
        }

        for (i = 0; i < sLen; i += 2)
        {
            lr[0] ^= StreamToWord(saltBytes, ref saltOffset);
            lr[1] ^= StreamToWord(saltBytes, ref saltOffset);
            Encipher(lr, 0);
            _s[i] = lr[0];
            _s[i + 1] = lr[1];
        }
    }
}
#endif
