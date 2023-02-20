/*
The MIT License (MIT)
Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
Copyright (c) 2013 Ryan D. Emerle (.Net port)
Copyright (c) 2016/2022 Chris McKee (.Net-core port / patches / new features)

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

using System;
using System.Security.Cryptography;
using System.Text;

namespace nBCrypt
{
    /// <summary>BCrypt implementation.</summary>
    /// <remarks>
    ///  <para>
    ///        BCrypt implements OpenBSD-style Blowfish password hashing using the scheme described in
    ///        <a href="http://www.usenix.org/event/usenix99/provos/provos_html/index.html">"A Future-
    ///        Adaptable Password Scheme"</a> by Niels Provos and David Mazieres.
    ///  </para>
    ///  <para>
    ///        This password hashing system tries to thwart off-line password cracking using a
    ///        computationally-intensive hashing algorithm, based on Bruce Schneier's Blowfish cipher.
    ///        The work factor of the algorithm is parameterised, so it can be increased as computers
    ///        get faster.
    ///  </para>
    ///  <para>
    ///        To hash a password using the defaults, call the <see cref="BCrypt.HashPassword(string)"/> (which will generate a random salt and hash at default cost), like this:
    ///  </para>
    ///  <code>string pw_hash = BCrypt.HashPassword(plain_password);</code>
    ///  <para>
    ///         To hash a password using SHA384 pre-hashing for increased entropy call <see cref="BCrypt.EnhancedHashPassword(string)"/>
    ///         (which will generate a random salt and hash at default cost), like this:
    ///  </para>
    ///  <code>string pw_hash = BCrypt.EnhancedHashPassword(plain_password);</code>
    ///  <para>
    ///        To check whether a plaintext password matches one that has been hashed previously,
    ///        use the <see cref="BCrypt.Verify(string, string, bool, HashType)"/> method:
    ///        (To validate an enhanced hash you can pass true as the last parameter of Verify or use  <see cref="BCrypt.EnhancedVerify(string, string, HashType)"/>)
    ///  </para>
    ///  <code>
    ///     if (BCrypt.Verify(candidate_password, stored_hash))
    ///         Console.WriteLine("It matches");
    ///     else
    ///         Console.WriteLine("It does not match");
    ///   </code>
    ///   <para>
    ///         The <see cref="GenerateSalt(int,char)"/> method takes an optional parameter (workFactor) that
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
    public class BCrypt : BCryptCore
    {
        /// <summary>
        /// Validate existing hash and password,
        /// </summary>
        /// <param name="currentKey">Current password / string</param>
        /// <param name="currentHash">Current hash to validate password against</param>
        /// <param name="newKey">NEW password / string to be hashed</param>
        /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
        ///                          factor therefore increases as 2^workFactor. Default is 11</param>
        /// <param name="forceWorkFactor">By default this method will not accept a work factor lower
        /// than the one set in the current hash and will set the new work-factor to match.</param>
        /// <exception cref="BcryptAuthenticationException">returned if the users hash and current pass doesn't validate</exception>
        /// <exception cref="SaltParseException">returned if the salt is invalid in any way</exception>
        /// <exception cref="ArgumentException">returned if the hash is invalid</exception>
        /// <exception cref="ArgumentNullException">returned if the user hash is null</exception>
        /// <returns>New hash of new password</returns>
        public static string ValidateAndReplacePassword(string currentKey, string currentHash, string newKey,
            int workFactor = DefaultRounds, bool forceWorkFactor = false) =>
            ValidateAndReplacePassword(currentKey, currentHash, false, HashType.None, newKey, false, HashType.None,
                workFactor, forceWorkFactor);


        /// <summary>
        /// Validate existing hash and password,
        /// </summary>
        /// <param name="currentKey">Current password / string</param>
        /// <param name="currentHash">Current hash to validate password against</param>
        /// <param name="currentKeyEnhancedEntropy">Set to true,the string will undergo SHA384 hashing to make
        /// use of available entropy prior to bcrypt hashing</param>
        /// <param name="oldHashType">HashType used (default SHA384)</param>
        ///
        /// <param name="newKey">NEW password / string to be hashed</param>
        /// <param name="newKeyEnhancedEntropy">Set to true,the string will undergo SHA384 hashing to make
        /// use of available entropy prior to bcrypt hashing</param>
        /// <param name="newHashType">HashType to use (default SHA384)</param>
        /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
        ///                          factor therefore increases as 2^workFactor. Default is 11</param>
        /// <param name="forceWorkFactor">By default this method will not accept a work factor lower
        /// than the one set in the current hash and will set the new work-factor to match.</param>
        /// <exception cref="BcryptAuthenticationException">returned if the users hash and current pass doesn't validate</exception>
        /// <exception cref="SaltParseException">returned if the salt is invalid in any way</exception>
        /// <exception cref="ArgumentException">returned if the hash is invalid</exception>
        /// <exception cref="ArgumentNullException">returned if the user hash is null</exception>
        /// <returns>New hash of new password</returns>
        public static string ValidateAndReplacePassword(string currentKey, string currentHash,
            bool currentKeyEnhancedEntropy, HashType oldHashType,
            string newKey, bool newKeyEnhancedEntropy = false, HashType newHashType = DefaultEnhancedHashType,
            int workFactor = DefaultRounds, bool forceWorkFactor = false)
        {
            if (currentKey == null)
            {
                throw new ArgumentNullException(nameof(currentKey));
            }

            if (string.IsNullOrEmpty(currentHash))
            {
                throw new ArgumentException("Invalid Hash", nameof(currentHash));
            }

            if (Verify(currentKey, currentHash, currentKeyEnhancedEntropy, oldHashType))
            {
                // Determine the starting offset and validate the salt
                int startingOffset;

                if (currentHash[0] != '$' || currentHash[1] != '2')
                {
                    throw new SaltParseException("Invalid bcrypt version");
                }
                else if (currentHash[2] == '$')
                {
                    startingOffset = 3;
                }
                else
                {
                    char minor = currentHash[2];
                    if (minor != 'a' && minor != 'b' && minor != 'x' && minor != 'y' || currentHash[3] != '$')
                    {
                        throw new SaltParseException("Invalid bcrypt revision");
                    }

                    startingOffset = 4;
                }

                // Extract number of rounds
                if (currentHash[startingOffset + 2] > '$')
                {
                    throw new SaltParseException("Missing work factor");
                }

                // Extract details from salt
                int currentWorkFactor = Convert.ToInt16(currentHash.Substring(startingOffset, 2));

                // Throw if log rounds are out of range on hash, deals with custom salts
                if (workFactor < 1 || workFactor > 31)
                {
                    throw new SaltParseException("Work factor out of range");
                }

                // Never downgrade work-factor (unless forced)
                if (!forceWorkFactor && currentWorkFactor > workFactor)
                {
                    workFactor = currentWorkFactor;
                }

                return HashPassword(newKey, GenerateSalt(workFactor), newKeyEnhancedEntropy, newHashType);
            }

            throw new BcryptAuthenticationException("Current credentials could not be authenticated");
        }

        /// <summary>
        ///  Verifies that the hash of the given <paramref name="text"/> matches the provided
        ///  <paramref name="hash"/>
        /// </summary>
        /// <param name="text">The text to verify.</param>
        /// <param name="hash"> The previously-hashed password.</param>
        /// <param name="enhancedEntropy">Set to true,the string will undergo SHA384 hashing to make use of available entropy prior to bcrypt hashing</param>
        /// <param name="hashType">HashType used (default SHA384)</param>
        /// <returns>true if the passwords match, false otherwise.</returns>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values.</exception>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static bool Verify(string text, string hash, bool enhancedEntropy = false,
            HashType hashType = DefaultEnhancedHashType)
        {
            return SecureEquals(SafeUTF8.GetBytes(hash),
                SafeUTF8.GetBytes(HashPassword(text, hash, enhancedEntropy, hashType)));
        }

        /// <summary>
        ///  Hash a password using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int,char)"/>.
        /// </summary>
        /// <param name="inputKey">The password to hash.</param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string HashPassword(string inputKey) => HashPassword(inputKey, GenerateSalt());


        /// <summary>
        ///  Hash a password using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int,char)"/> using the given <paramref name="workFactor"/>.
        /// </summary>
        /// <param name="inputKey">     The password to hash.</param>
        /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
        ///                          factor therefore increases as 2^workFactor. Default is 11</param>
        /// <param name="enhancedEntropy">Set to true,the string will undergo SHA384 hashing to make use of available entropy prior to bcrypt hashing</param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string HashPassword(string inputKey, int workFactor, bool enhancedEntropy = false) =>
            HashPassword(inputKey, GenerateSalt(workFactor), enhancedEntropy);

        /// <summary>Hash a password using the OpenBSD BCrypt scheme.</summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values.</exception>
        /// <param name="inputKey">The password or string to hash.</param>
        /// <param name="salt">    the salt to hash with (best generated using <see cref="BCrypt.GenerateSalt(int,char)"/>).</param>
        /// <returns>The hashed password</returns>
        /// <exception cref="SaltParseException">Thrown when the <paramref name="salt"/> could not be parsed.</exception>
        public static string HashPassword(string inputKey, string salt) => HashPassword(inputKey, salt, false);

        /// <summary>Hash a password using the OpenBSD BCrypt scheme.</summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values.</exception>
        /// <param name="inputKey">The password or string to hash.</param>
        /// <param name="salt">    the salt to hash with (best generated using <see cref="BCrypt.GenerateSalt(int,char)"/>).</param>
        /// <param name="enhancedEntropy">Set to true,the string will undergo hashing (defaults to SHA384 then base64 encoding) to make use of available entropy prior to bcrypt hashing</param>
        /// <param name="hashType">Configurable hash type for enhanced entropy</param>
        /// <returns>The hashed password</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="inputKey"/> is null.</exception>
        /// <exception cref="SaltParseException">Thrown when the <paramref name="salt"/> could not be parsed.</exception>
        public static string HashPassword(string inputKey, string salt, bool enhancedEntropy, HashType hashType = DefaultEnhancedHashType)
        {
            if (inputKey == null)
            {
                throw new ArgumentNullException(nameof(inputKey));
            }

            if (string.IsNullOrEmpty(salt))
            {
                throw new ArgumentException("Invalid salt: salt cannot be null or empty", nameof(salt));
            }

            if (enhancedEntropy && hashType == HashType.None)
            {
                throw new ArgumentException(
                    "Invalid HashType, You can't have an enhanced hash with type none. HashType.None is used for internal clarity only.",
                    nameof(hashType));
            }

            // Determine the starting offset and validate the salt
            int startingOffset;
            char bcryptMinorRevision = (char)0;
            if (salt[0] != '$' || salt[1] != '2')
            {
                throw new SaltParseException("Invalid salt version");
            }
            else if (salt[2] == '$')
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
            int workFactor = Convert.ToInt16(salt.Substring(startingOffset, 2));

            // Throw if log rounds are out of range on hash, deals with custom salts
            if (workFactor < 1 || workFactor > 31)
            {
                throw new SaltParseException("Salt rounds out of range");
            }

            string extractedSalt = salt.Substring(startingOffset + 3, 22);

            byte[] inputBytes;

            if (enhancedEntropy)
            {
                inputBytes = EnhancedHash(SafeUTF8.GetBytes(inputKey), bcryptMinorRevision, hashType);
            }
            else
            {
                inputBytes = SafeUTF8.GetBytes(inputKey + (bcryptMinorRevision >= 'a' ? Nul : EmptyString));
            }

            byte[] saltBytes = DecodeBase64(extractedSalt, BCryptSaltLen);

            BCrypt bCrypt = new BCrypt();

            byte[] hashed = bCrypt.CryptRaw(inputBytes, saltBytes, workFactor);

            // Generate result string
            var result = new StringBuilder(60);
            result.Append("$2").Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2")).Append('$');
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
        public static string GenerateSalt(int workFactor = DefaultRounds, char bcryptMinorRevision = DefaultHashVersion)
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
            result.Append("$2").Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2")).Append('$');
            result.Append(EncodeBase64(saltBytes, saltBytes.Length));

            return result.ToString();
        }


        /// <summary>
        /// Based on password_needs_rehash in PHP this method will return true
        /// if the work factor (logrounds) set on the hash is lower than the new minimum workload passed in
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

        #region Enhanced Specific Methods

        /// <summary>
        ///  Pre-hash a password with SHA384 then using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int,char)"/>.
        /// </summary>
        /// <param name="inputKey">The password to hash.</param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string EnhancedHashPassword(string inputKey) => HashPassword(inputKey, GenerateSalt(), true);

        /// <summary>
        ///  Pre-hash a password with SHA384 then using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int,char)"/>.
        /// </summary>
        /// <param name="inputKey">The password to hash.</param>
        /// <param name="workFactor"></param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string EnhancedHashPassword(string inputKey, int workFactor) =>
            HashPassword(inputKey, GenerateSalt(workFactor), true);

        /// <summary>
        ///  Pre-hash a password with SHA384 then using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int,char)"/>.
        /// </summary>
        /// <param name="inputKey">The password to hash.</param>
        /// <param name="workFactor"></param>
        /// <param name="hashType">Configurable hash type for enhanced entropy</param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string EnhancedHashPassword(string inputKey, int workFactor, HashType hashType) =>
            HashPassword(inputKey, GenerateSalt(workFactor), true, hashType);


        /// <summary>
        ///  Pre-hash a password with SHA384 then using the OpenBSD BCrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int,char)"/>.
        /// </summary>
        /// <param name="inputKey">The password to hash.</param>
        /// <param name="workFactor">Defaults to 11</param>
        /// <param name="hashType">Configurable hash type for enhanced entropy</param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string EnhancedHashPassword(string inputKey, HashType hashType, int workFactor = DefaultRounds) =>
            HashPassword(inputKey, GenerateSalt(workFactor), true, hashType);


        /// <summary>
        /// Hashes key, base64 encodes before returning byte array
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <param name="bcryptMinorRevision"></param>
        /// <param name="hashType"></param>
        /// <returns></returns>
        private static byte[] EnhancedHash(byte[] inputBytes, char bcryptMinorRevision, HashType hashType)
        {
            switch (hashType)
            {
                case HashType.SHA256:
                    using (var sha = SHA256.Create())
                        inputBytes = SafeUTF8.GetBytes(Convert.ToBase64String(sha.ComputeHash(inputBytes)) +
                                                       (bcryptMinorRevision >= 'a' ? Nul : EmptyString));
                    break;
                case HashType.SHA384:
                    using (var sha = SHA384.Create())
                        inputBytes = SafeUTF8.GetBytes(Convert.ToBase64String(sha.ComputeHash(inputBytes)) +
                                                       (bcryptMinorRevision >= 'a' ? Nul : EmptyString));
                    break;
                case HashType.SHA512:
                    using (var sha = SHA512.Create())
                        inputBytes = SafeUTF8.GetBytes(Convert.ToBase64String(sha.ComputeHash(inputBytes)) +
                                                       (bcryptMinorRevision >= 'a' ? Nul : EmptyString));
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashType), hashType, null);
            }

            return inputBytes;
        }

        /// <summary>
        ///  Verifies that the hash of the given <paramref name="text"/> matches the provided
        ///  <paramref name="hash"/>; the string will undergo SHA384 hashing to maintain the enhanced entropy work done during hashing
        /// </summary>
        /// <param name="text">The text to verify.</param>
        /// <param name="hash"> The previously-hashed password.</param>
        /// <param name="hashType">HashType used (default SHA384)</param>
        /// <returns>true if the passwords match, false otherwise.</returns>
        public static bool EnhancedVerify(string text, string hash, HashType hashType = DefaultEnhancedHashType) =>
            Verify(text, hash, true, hashType);

        #endregion
    }
}
