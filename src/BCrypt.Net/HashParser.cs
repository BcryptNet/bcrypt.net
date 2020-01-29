using System;

namespace BCrypt.Net
{
    internal static class HashParser
    {
        public static HashInformation GetHashInformation(string hash)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            if (hash.Length != 60
                || !hash.StartsWith("$2")
                || !IsValidBCryptVersionChar(hash[2])
                || hash[3] != '$'
                || hash[6] != '$')
            {
                ThrowInvalidHashFormat();
            }

            string workFactorAttempt = hash.Substring(4, 2);
            if (!int.TryParse(workFactorAttempt, out int workFactor)
                || workFactor < 0)
            {
                ThrowInvalidHashFormat();
            }

            for (int i = 7; i < hash.Length; ++i)
            {
                if (!IsValidBCryptBase64Char(hash[i]))
                {
                    ThrowInvalidHashFormat();
                }
            }

            return new HashInformation(hash.Substring(0, 6), hash.Substring(1, 2), workFactorAttempt, hash.Substring(7));
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

        private static void ThrowInvalidHashFormat()
        {
            throw new SaltParseException("Invalid Hash Format");
        }
    }
}
