using System;

namespace BCrypt.Net
{
    internal static class HashParser
    {
        public static HashInformation GetHashInformation(string hash)
        {
            if (!IsValidHash(hash))
            {
                ThrowInvalidHashFormat();
            }

            return new HashInformation(hash.Substring(0, 6), hash.Substring(1, 2), hash.Substring(4, 2), hash.Substring(7));
        }

        private static bool IsValidHash(string hash)
        {
            if (hash is null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            // Validate settings
            if (hash.Length != 60
                || !hash.StartsWith("$2")
                || !IsValidBCryptVersionChar(hash[2])
                || hash[3] != '$'
                || hash[6] != '$')
            {
                return false;
            }

            // Validate workfactor
            if (!IsAsciiNumeric(hash[4])
                || !IsAsciiNumeric(hash[5]))
            {
                return false;
            }

            // Validate hash
            for (int i = 7; i < hash.Length; ++i)
            {
                if (!IsValidBCryptBase64Char(hash[i]))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsValidBCryptVersionChar(char value)
        {
            return value == 'a'
                || value == 'b'
                || value == 'x'
                || value == 'y';
        }

        private static bool IsValidBCryptBase64Char(char value)
        {
            // Ordered by ascending ASCII value
            return value == '.'
                || value == '/'
                || (value >= '0' && value <= '9')
                || (value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z');
        }

        private static bool IsAsciiNumeric(char value)
        {
            return value >= '0' && value <= '9';
        }

        private static void ThrowInvalidHashFormat()
        {
            throw new SaltParseException("Invalid Hash Format");
        }
    }
}
