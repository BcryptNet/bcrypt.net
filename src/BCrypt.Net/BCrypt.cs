/*
The MIT License (MIT)
Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
Copyright (c) 2013 Ryan D. Emerle (.Net port)
Copyright (c) 2016/2025 Chris McKee (.Net-core port / patches / new features)

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

namespace BCryptNet
{
    /// <summary>BCrypt implementation.</summary>
    /// <remarks>
    ///  <para>
    ///        BCrypt implements OpenBSD-style Blowfish password hashing using the scheme described in
    ///        <a href="http://www.usenix.org/event/usenix99/provos/provos_html/index.html">
    ///        A Future-Adaptable Password Scheme</a> by Niels Provos and David Mazieres.
    ///  </para>
    ///  <para>
    ///        This password hashing system tries to thwart off-line password cracking using a
    ///        computationally-intensive hashing algorithm, based on Bruce Schneier's Blowfish cipher.
    ///        The work factor of the algorithm is parameterised, so it can be increased as computers
    ///        get faster.
    ///  </para>
    ///  <para>
    ///        To hash a password using the defaults, call the <see cref="HashPassword(string,int)"/> (which will generate a random salt and hash at default cost), like this:
    ///  </para>
    ///  <code>string pw_hash = BCrypt.HashPassword(plain_password);</code>
    ///  <para>
    ///         To hash a password using SHA384 pre-hashing for increased entropy see the <see cref="BCryptExtendedV2"/> class
    ///  </para>
    ///  <para>
    ///        To check whether a plaintext password matches one that has been hashed previously,
    ///        use the <see cref="Verify"/> method:
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
        /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
        ///                          factor therefore increases as 2^workFactor. Default is 11</param>
        /// <param name="forceWorkFactor">By default, this method will not accept a work factor lower
        /// than the one set in the current hash and will set the new work-factor to match.</param>
        /// <exception cref="BcryptAuthenticationException">returned if the users hash and current pass doesn't validate</exception>
        /// <exception cref="SaltParseException">returned if the salt is invalid in any way</exception>
        /// <exception cref="ArgumentException">returned if the hash is invalid</exception>
        /// <exception cref="ArgumentNullException">returned if the user hash is null</exception>
        /// <returns>New hash of new password</returns>
        public static string ValidateAndUpgradeHash(string currentKey, string currentHash, string newKey, int workFactor = DefaultRounds, bool forceWorkFactor = false)
        {
            if (currentKey == null)
                throw new ArgumentNullException(nameof(currentKey));

            if (string.IsNullOrEmpty(currentHash) || currentHash.Length != 60)
                throw new ArgumentException("Invalid Hash", nameof(currentHash));

            // Throw if validation fails (password isn't valid for hash)
            if (!Verify(currentKey, currentHash))
                throw new BcryptAuthenticationException("Current credentials could not be authenticated");

            // Throw if invalid BCrypt Version
            if (currentHash[0] != '$' || currentHash[1] != '2')
                throw new SaltParseException("Invalid bcrypt version");

            // Throw if log rounds are out of range on hash, deals with custom salts
            if (workFactor < 1 || workFactor > 31)
                throw new SaltParseException("Work factor out of range");

            // Determine the starting offset and validate the salt
            int startingOffset = 3;

            if (currentHash[2] != '$')
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

            // Never downgrade work-factor (unless forced)
            if (!forceWorkFactor && currentWorkFactor > workFactor)
            {
                workFactor = currentWorkFactor;
            }

            return HashPassword(newKey, GenerateSalt(workFactor));
        }

        /// <summary>
        ///  Verifies that the hash of the given <paramref name="text"/> matches the provided
        ///  <paramref name="hash"/>
        /// </summary>
        /// <param name="text">The text to verify.</param>
        /// <param name="hash"> The previously-hashed password.</param>
        /// <returns>true if the passwords match, false otherwise.</returns>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values.</exception>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static bool Verify(string text, string hash)
        {
            return SecureEquals(SafeUTF8.GetBytes(hash), SafeUTF8.GetBytes(HashPassword(text, hash)));
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
        ///  Hash a password using the OpenBSD BCrypt scheme with a manually supplied salt/>.
        /// </summary>
        /// <remarks>
        ///  You should generally leave generating salts to the library.
        /// </remarks>
        /// <param name="inputKey">The password to hash.</param>
        /// <param name="salt">The log2 of the number of rounds of hashing to apply - the work
        ///                          factor therefore increases as 2^workFactor. Default is 11</param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="SaltParseException">Thrown when the salt could not be parsed.</exception>
        public static string HashPassword(string inputKey, string salt) => CreatePasswordHash(inputKey, salt);


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
    }
}
