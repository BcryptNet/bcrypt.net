using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace BCryptNet.BenchMarks.DecodeB64
{
    internal static class DecodeB64Methods
    {
        private static readonly int[] Index64 = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, 0, 1, 54, 55,
            56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
            -1, -1, -1, -1, -1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
            -1, -1, -1, -1, -1, -1, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
            51, 52, 53, -1, -1, -1, -1, -1
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Char64(char character)
        {
            return character < 0 || character > Index64.Length ? -1 : Index64[character];
        }

        // Methods

        public static byte[] DecodeBase64ToBytes(string encodedString, int maximumBytes)
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

        internal static byte[] DecodeBase64StringCreateSpan(string encodedString, int maximumBytes)
        {

            int sourceLength = encodedString.Length;
            int outputLength = 0;

            if (maximumBytes <= 0)
            {
                throw new ArgumentException("Invalid maximum bytes value", nameof(maximumBytes));
            }

            var rs = string.Create(maximumBytes, encodedString, (chars, buff) =>
            {
                int position = 0;
                int charpos = 0;

                while (position < sourceLength - 1 && outputLength < maximumBytes)
                {
                    int c1 = Char64(buff[position++]);
                    int c2 = Char64(buff[position++]);
                    if (c1 == -1 || c2 == -1)
                    {
                        break;
                    }

                    chars[charpos] = (char)((c1 << 2) | ((c2 & 0x30) >> 4));
                    charpos++;

                    if (++outputLength >= maximumBytes || position >= sourceLength)
                    {
                        break;
                    }

                    int c3 = Char64(buff[position++]);
                    if (c3 == -1)
                    {
                        break;
                    }

                    chars[charpos] = ((char)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)));
                    charpos++;
                    if (++outputLength >= maximumBytes || position >= sourceLength)
                    {
                        break;
                    }

                    int c4 = Char64(buff[position++]);
                    chars[charpos] = ((char)(((c3 & 0x03) << 6) | c4));
                    charpos++;
                    ++outputLength;
                }
            }).AsSpan();

            Span<byte> ret = new byte[outputLength];

            for (var i = 0; i < outputLength; i++)
            {
                ret[i] = (byte)rs[i];
            }

            return ret.ToArray();
        }
        internal static byte[] DecodeBase64StandardSized(string encodedString, int maximumBytes)
        {
            int sourceLength = encodedString.Length;
            int outputLength = 0;

            if (maximumBytes <= 0)
            {
                throw new ArgumentException("Invalid maximum bytes value", nameof(maximumBytes));
            }

            int position = 0;
            StringBuilder rs = new StringBuilder(maximumBytes);
            while (position < sourceLength - 1 && outputLength < maximumBytes)
            {
                int c1 = Char64(encodedString[position++]);
                int c2 = Char64(encodedString[position++]);
                if (c1 == -1 || c2 == -1)
                {
                    break;
                }

                rs.Append((char)((c1 << 2) | ((c2 & 0x30) >> 4)));
                if (++outputLength >= maximumBytes || position >= sourceLength)
                {
                    break;
                }

                int c3 = Char64(encodedString[position++]);
                if (c3 == -1)
                {
                    break;
                }

                rs.Append((char)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)));
                if (++outputLength >= maximumBytes || position >= sourceLength)
                {
                    break;
                }

                int c4 = Char64(encodedString[position++]);
                rs.Append((char)(((c3 & 0x03) << 6) | c4));

                ++outputLength;
            }
            var bval = new byte[outputLength];
            for (var i = 0; i < outputLength; i++)
            {
                bval[i] = (byte)rs[i];
            }
            return bval;

        }

        internal static byte[] DecodeBase64StandardUnSized(string encodedString, int maximumBytes)
        {

            int sourceLength = encodedString.Length;
            int outputLength = 0;

            if (maximumBytes <= 0)
            {
                throw new ArgumentException("Invalid maximum bytes value", nameof(maximumBytes));
            }

            int position = 0;
            StringBuilder rs = new StringBuilder();
            while (position < sourceLength - 1 && outputLength < maximumBytes)
            {
                int c1 = Char64(encodedString[position++]);
                int c2 = Char64(encodedString[position++]);
                if (c1 == -1 || c2 == -1)
                {
                    break;
                }

                rs.Append((char)((c1 << 2) | ((c2 & 0x30) >> 4)));
                if (++outputLength >= maximumBytes || position >= sourceLength)
                {
                    break;
                }

                int c3 = Char64(encodedString[position++]);
                if (c3 == -1)
                {
                    break;
                }

                rs.Append((char)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)));
                if (++outputLength >= maximumBytes || position >= sourceLength)
                {
                    break;
                }

                int c4 = Char64(encodedString[position++]);
                rs.Append((char)(((c3 & 0x03) << 6) | c4));

                ++outputLength;
            }
            var bval = new byte[outputLength];
            for (var i = 0; i < outputLength; i++)
            {
                bval[i] = (byte)rs[i];
            }
            return bval;

        }

        public static int DecodeBase64SpanBuffer(ReadOnlySpan<char> encodedSpan, Span<byte> destination)
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
    }
}
