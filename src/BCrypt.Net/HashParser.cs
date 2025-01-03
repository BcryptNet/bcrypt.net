using System;

namespace BCryptNet
{
    /// <summary>
    /// Hash Parser
    /// </summary>
    public static class HashParser
    {
        private static readonly HashFormatDescriptor OldFormatDescriptor = new HashFormatDescriptor(versionLength: 1);
        private static readonly HashFormatDescriptor NewFormatDescriptor = new HashFormatDescriptor(versionLength: 2);

        /// <summary>
        /// Get Hash Info
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static HashInformation GetHashInformation(string hash)
        {
            if (!IsValidHash(hash, out var format))
            {
                ThrowInvalidHashFormat();
            }

            var workFactor = 10 * (hash[format.WorkfactorOffset] - '0') + (hash[format.WorkfactorOffset + 1] - '0');

            return new HashInformation(
                hash.Substring(0, format.SettingLength),
                hash.Substring(1, format.VersionLength),
                workFactor,
                hash.Substring(format.HashOffset));
        }

        /// <summary>
        /// Get Work Factor
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static int GetWorkFactor(string hash)
        {
            if (!IsValidHash(hash, out var format))
            {
                ThrowInvalidHashFormat();
            }
            
            return 10 * (hash[format.WorkfactorOffset] - '0') + (hash[format.WorkfactorOffset + 1] - '0');
        }

        /// <summary>
        /// Get Salt from Hash
        /// </summary>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static string GetSalt(string hash)
        {
            if (!IsValidHash(hash, out var format))
            {
                ThrowInvalidHashFormat();
            }
            if (string.IsNullOrWhiteSpace(hash) || hash.Length < 29)
            {
                throw new ArgumentException("Invalid BCrypt hash.");
            }

            return hash.Substring(0, 22 + format.HashOffset);
        }

        internal static bool IsValidHash(string hash, out HashFormatDescriptor format)
        {
            if (hash is null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            if (hash.Length != 59 && hash.Length != 60)
            {
                // Incorrect full hash length
                format = null;
                return false;
            }

            if (!hash.StartsWith("$2"))
            {
                // Not a bcrypt hash
                format = null;
                return false;
            }

            // Validate version
            int offset = 2;
            if (IsValidBCryptVersionChar(hash[offset]))
            {
                offset++;
                format = NewFormatDescriptor;
            }
            else
            {
                format = OldFormatDescriptor;
            }

            if (hash[offset++] != '$')
            {
                format = null;
                return false;
            }

            // Validate workfactor
            if (!IsAsciiNumeric(hash[offset++])
                || !IsAsciiNumeric(hash[offset++]))
            {
                format = null;
                return false;
            }

            if (hash[offset++] != '$')
            {
                format = null;
                return false;
            }

            // Validate hash
            for (int i = offset; i < hash.Length; ++i)
            {
                if (!IsValidBCryptBase64Char(hash[i]))
                {
                    format = null;
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

        internal class HashFormatDescriptor
        {
            public HashFormatDescriptor(int versionLength)
            {
                VersionLength = versionLength;
                WorkfactorOffset = 1 + VersionLength + 1;
                SettingLength = WorkfactorOffset + 2;
                HashOffset = SettingLength + 1;
            }

            public int VersionLength { get; }

            public int WorkfactorOffset { get; }

            public int SettingLength { get; }

            public int HashOffset { get; }
        }
    }
}
