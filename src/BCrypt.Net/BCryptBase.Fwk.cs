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

/// <summary>
/// .Net Framework (pre-span) implementation
/// </summary>
public partial class BCryptCore
{
    #if !NETCOREAPP
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
    internal static string CreatePasswordHash(string inputKey, string salt, HashType hashType = HashType.None, Func<string, HashType, char, byte[]> enhancedHashKeyGen = null)
    {
        if (string.IsNullOrEmpty(salt))
        {
            throw new ArgumentException("Invalid salt: salt cannot be null or empty", nameof(salt));
        }

        if (hashType == HashType.None && inputKey.Length > 72)
        {
            throw new ArgumentException("Invalid input key: input key cannot exceed 72 characters for bCrypt", nameof(inputKey));
        }

        if (enhancedHashKeyGen == null && hashType != HashType.None)
        {
            throw new ArgumentException("Invalid HashType, You can't have an enhanced hash without an implementation of the key generator.", nameof(hashType));
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
        if (salt[startingOffset + 2] > '$')
        {
            throw new SaltParseException("Missing salt rounds");
        }

        // Extract details from salt
        int workFactor = Convert.ToInt16(salt.Substring(startingOffset, 2), CultureInfo.InvariantCulture);

        // Throw if log rounds are out of range on hash, deals with custom salts
        if (workFactor < 1 || workFactor > 31)
        {
            throw new SaltParseException("Salt rounds out of range");
        }

        byte[] inputBytes;
        switch (hashType)
        {
            case HashType.None:
                inputBytes = SafeUTF8.GetBytes(inputKey + (bcryptMinorRevision >= 'a' ? Nul : EmptyString));
                break;
            default:
                if (enhancedHashKeyGen == null)
                {
                    throw new ArgumentException("Invalid HashType, You can't have an enhanced hash without an implementation of the key generator.", nameof(hashType));
                }

                inputBytes = enhancedHashKeyGen(inputKey, hashType, bcryptMinorRevision);
                break;
        }


        return HashBytes(inputBytes, salt.Substring(startingOffset + 3, 22), bcryptMinorRevision, workFactor);
    }

    internal static string HashBytes(byte[] inputBytes, string extractedSalt, char bcryptMinorRevision, int workFactor)
    {
        byte[] saltBytes = DecodeBase64(extractedSalt, BCryptSaltLen);

        BCrypt bCrypt = new BCrypt();

        byte[] hashed = bCrypt.CryptRaw(inputBytes, saltBytes, workFactor);

        // Generate result string
        var result = new StringBuilder(60);
        result.Append('$').Append('2').Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2", CultureInfo.InvariantCulture)).Append('$');
        result.Append(EncodeBase64(saltBytes, saltBytes.Length));
        result.Append(EncodeBase64(hashed, (BfCryptCiphertextLength * 4) - 1));

        return result.ToString();
    }

    /// <summary>
    ///  Generate a salt for use with the <see cref="BCrypt.HashPassword(string, string)"/> method.
    /// </summary>
    /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
    ///                          factor therefore increases as 2**workFactor.</param>
    /// <param name="bcryptMinorRevision"></param>
    /// <exception cref="ArgumentOutOfRangeException">Work factor must be between 4 and 31</exception>
    /// <returns>A base64 encoded salt value.</returns>
    /// <exception cref="ArgumentException">BCrypt Revision should be a, b, x or y</exception>
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
        result.Append(EncodeBase64(saltBytes, saltBytes.Length));

        return result.ToString();
    }

    /// <summary>
    ///  Encode a byte array using BCrypt's slightly-modified base64 encoding scheme. Note that this
    ///  is *not* compatible with the standard MIME-base64 encoding.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
    ///                                     illegal values.</exception>
    /// <param name="byteArray">The byte array to encode.</param>
    /// <param name="length">   The number of bytes to encode.</param>
    /// <returns>Base64-encoded string.</returns>
    internal static char[] EncodeBase64(byte[] byteArray, int length)
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
    /// <param name="encodedString">The string to decode.</param>
    /// <param name="maximumBytes"> The maximum bytes to decode.</param>
    /// <returns>The decoded byte array.</returns>
    internal static byte[] DecodeBase64(string encodedString, int maximumBytes)
    {
        int sourceLength = encodedString.Length;
        int outputLength = 0;

        if (maximumBytes <= 0)
        {
            throw new ArgumentException("Invalid maximum bytes value", nameof(maximumBytes));
        }

        byte[] result = new byte[maximumBytes];

        int position = 0;
        while (position < sourceLength - 1 && outputLength < maximumBytes)
        {
            int c1 = Char64(encodedString[position++]);
            int c2 = Char64(encodedString[position++]);
            if (c1 == -1 || c2 == -1)
            {
                break;
            }

            result[outputLength] = (byte)((c1 << 2) | ((c2 & 0x30) >> 4));
            if (++outputLength >= maximumBytes || position >= sourceLength)
            {
                break;
            }

            int c3 = Char64(encodedString[position++]);
            if (c3 == -1)
            {
                break;
            }

            result[outputLength] = (byte)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2));
            if (++outputLength >= maximumBytes || position >= sourceLength)
            {
                break;
            }

            int c4 = Char64(encodedString[position++]);
            result[outputLength] = (byte)(((c3 & 0x03) << 6) | c4);

            ++outputLength;
        }

        return result;
    }

    /// <summary>Blowfish encipher a single 64-bit block encoded as two 32-bit halves.</summary>
    /// <param name="blockArray">An array containing the two 32-bit half blocks. The plaintext to be encrypted</param>
    /// <param name="offset">    The position in the array of the blocks.</param>
    private void Encipher(uint[] blockArray, int offset)
    {
        uint block = blockArray[offset];
        uint r = blockArray[offset + 1];

        block ^= _p[0];

        unchecked
        {
            uint round;
            for (round = 0; round <= BlowfishNumRounds - 2;)
            {
                // Feistel substitution on left word
                uint n = _s[(block >> 24) & 0xff];
                n += _s[0x100 | ((block >> 16) & 0xff)];
                n ^= _s[0x200 | ((block >> 8) & 0xff)];
                n += _s[0x300 | (block & 0xff)];
                r ^= n ^ _p[++round];

                // Feistel substitution on right word
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
    private static uint StreamToWord(byte[] data, ref int offset)
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
    private void Key(byte[] keyBytes)
    {
        int i;
        int kOfP = 0;

        uint[] lr = { 0, 0 };
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
    private void EKSKey(byte[] saltBytes, byte[] inputBytes)

    {
        int i;
        int passwordOffset = 0;
        int saltOffset = 0;

        uint[] lr = { 0, 0 };
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

    /// <summary>Perform the central hashing step in the BCrypt scheme.</summary>
    /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
    ///                                     illegal values.</exception>
    /// <param name="inputBytes">The input byte array to hash.</param>
    /// <param name="saltBytes"> The salt byte array to hash with.</param>
    /// <param name="workFactor"> The binary logarithm of the number of rounds of hashing to apply.</param>
    /// <returns>A byte array containing the hashed result.</returns>
    internal byte[] CryptRaw(byte[] inputBytes, byte[] saltBytes, int workFactor)
    {
        int i;
        int j;

        uint[] cdata = new uint[BfCryptCiphertext.Length];
        Array.Copy(BfCryptCiphertext, cdata, BfCryptCiphertext.Length);

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
        byte[] ret = new byte[clen * 4];
        for (i = 0, j = 0; i < clen; i++)
        {
            // per-line extract first byte by shifting cdata word at index right 24 bits
            // using >> op then isolate the least significant byte using mask 0xff
            ret[j++] = (byte)((cdata[i] >> 24) & 0xff);
            ret[j++] = (byte)((cdata[i] >> 16) & 0xff);
            ret[j++] = (byte)((cdata[i] >> 8) & 0xff);
            ret[j++] = (byte)(cdata[i] & 0xff);
        }

        return ret;
    }
#endif

}
