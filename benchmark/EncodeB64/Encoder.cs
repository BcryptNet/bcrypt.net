using System;
using System.Text;

namespace BCryptNet.BenchMarks.EncodeB64
{
    internal static class EncodeB64Methods
    {
        private static readonly char[] Base64Code =
        {
            '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
            'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8',
            '9'
        };

        public static string EncodeBase64Unsized(byte[] byteArray, int length)
        {
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int off = 0;
            StringBuilder rs = new StringBuilder();
            while (off < length)
            {
                int c1 = byteArray[off++] & 0xff;
                rs.Append(Base64Code[(c1 >> 2) & 0x3f]);
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    rs.Append(Base64Code[c1 & 0x3f]);
                    break;
                }

                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                rs.Append(Base64Code[c1 & 0x3f]);
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    rs.Append(Base64Code[c1 & 0x3f]);
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                rs.Append(Base64Code[c1 & 0x3f]);
                rs.Append(Base64Code[c2 & 0x3f]);
            }

            return rs.ToString();
        }

        public static string EncodeBase64Sized(byte[] byteArray, int length)
        {
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int off = 0;
            StringBuilder rs = new StringBuilder(length);
            while (off < length)
            {
                int c1 = byteArray[off++] & 0xff;
                rs.Append(Base64Code[(c1 >> 2) & 0x3f]);
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    rs.Append(Base64Code[c1 & 0x3f]);
                    break;
                }
                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                rs.Append(Base64Code[c1 & 0x3f]);
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    rs.Append(Base64Code[c1 & 0x3f]);
                    break;
                }
                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                rs.Append(Base64Code[c1 & 0x3f]);
                rs.Append(Base64Code[c2 & 0x3f]);
            }
            return rs.ToString();
        }

        public static char[] EncodeBase64AsBytes(byte[] byteArray, int length)
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
                int c1 = byteArray[off++] & 0xff;
                encoded[pos++] = (Base64Code[(c1 >> 2) & 0x3f]);
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = (Base64Code[c1 & 0x3f]);
                    break;
                }

                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = (Base64Code[c1 & 0x3f]);
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = (Base64Code[c1 & 0x3f]);
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = (Base64Code[c1 & 0x3f]);
                encoded[pos++] = (Base64Code[c2 & 0x3f]);
            }

            return encoded;
        }

        internal static ReadOnlySpan<char> EncodeBase64StackAlloc(ReadOnlySpan<byte> byteArray, int length)
        {
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
            Span<char> encoded = stackalloc char[encodedSize];

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

            return encoded.ToArray();
        }

        internal static ReadOnlySpan<char> EncodeBase64HeapAlloc(ReadOnlySpan<byte> byteArray, int length)
        {
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
            Span<char> encoded = new char[encodedSize];

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
    }
}
