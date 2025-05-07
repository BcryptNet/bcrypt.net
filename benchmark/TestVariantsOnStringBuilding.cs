using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks.EncodeB64;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    [MemoryDiagnoser]
    /*[RPlotExporter]*/[RankColumn]
    //[GcServer(true)]
    [Orderer(SummaryOrderPolicy.Declared)]
    [KeepBenchmarkFiles]
    [MarkdownExporterAttribute.GitHub]
    [ReturnValueValidator(failOnError: true)]
    [IterationTime(500)]
    public class TestVariantsOnStringBuilding
    {
        private readonly string bcryptMinorRevision = "a";
        private static readonly string hash = "TV4S6ytwfsfvkgY8jIucDrjc8deX1s.";
        private static readonly string salt = "DCq7YPn5Rq63x1Lad4cll.";

        private static readonly byte[] SaltBytes = BCryptBaseLine.BCrypt.DecodeBase64(salt, 16);
        private static readonly byte[] HashBytes = BCryptBaseLine.BCrypt.DecodeBase64(hash, 23);

        private static readonly char[] EncodedSaltAsChars = EncodeB64Methods.EncodeBase64AsBytes(SaltBytes, 16);
        private static readonly char[] EncodedHashAsChars = EncodeB64Methods.EncodeBase64AsBytes(HashBytes, 23);

        private readonly int workFactor = 6;

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("StringAppend", "AppendString")]
        public string Original_StrBuilder_SinEncoding()
        {
            // Generate result string
            StringBuilder result = new StringBuilder();
            result.AppendFormat("$2{1}${0:00}$", workFactor, bcryptMinorRevision);
            result.Append(salt);
            result.Append(hash);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string StrBuilder_SinEncoding_UsingAppendFormatAndAppendChar()
        {
            // Generate result string
            StringBuilder result = new StringBuilder();
            result.AppendFormat("$2{1}${0:00}$", workFactor, bcryptMinorRevision);
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string SizedStrBuilder_SinEncoding_UsingAppendFormatAndAppendChar()
        {
            // Generate result string
            StringBuilder result = new StringBuilder(60);
            result.AppendFormat("$2{1}${0:00}$", workFactor, bcryptMinorRevision);
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string SizedStrBuilder_SinEncoding_UsingAppendStringAndChar()
        {
            var result = new StringBuilder(60);
            result.Append("$2");
            result.Append(bcryptMinorRevision);
            result.Append('$');
            result.Append(workFactor.ToString("D2"));
            result.Append('$');
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string SizedStrBuilder_SinEncoding_UsingAppendStringAndChar_v2()
        {
            var result = new StringBuilder(60);
            result.Append('$');
            result.Append('2');
            result.Append(bcryptMinorRevision);
            result.Append('$');
            result.Append(workFactor.ToString("D2", CultureInfo.InvariantCulture));
            result.Append('$');
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string SizedStrBuilder_SinEncoding_UsingAppendStrings_HashSaltAsChar()
        {
            var result = new StringBuilder(60);
            result.Append("$2");
            result.Append(bcryptMinorRevision);
            result.Append("$");
            result.Append(workFactor.ToString("D2"));
            result.Append("$");
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendString")]
        public string SizedStrBuilder_SinEncoding_UsingAppendStrings_HashSaltAsString_WorkFactorToString()
        {
            var result = new StringBuilder(60);
            result.Append("$2");
            result.Append(bcryptMinorRevision);
            result.Append("$");
            result.Append(workFactor.ToString("D2"));
            result.Append("$");
            result.Append(salt);
            result.Append(hash);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendString")]
        public string SizedStrBuilder_SinEncoding_UsingAppendStrings_WorkFactorInterpolated()
        {
            var result = new StringBuilder(60);
            result.Append("$2");
            result.Append(bcryptMinorRevision);
            result.Append("$");
            result.Append($"{workFactor:00}");
            result.Append("$");
            result.Append(salt);
            result.Append(hash);

            return result.ToString();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static char[] Concatenate(char[] array1, char[] array2)
        {
            char[] result = new char[array1.Length + array2.Length];
            array1.CopyTo(result, 0);
            array2.CopyTo(result, array1.Length);
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static string ConcatenateToString(char[] array1, char[] array2)
        {
            Span<char> result = stackalloc char[array1.Length + array2.Length];
            array1.CopyTo(result);
            array2.CopyTo(result.Slice(array1.Length));
            return new string(result);
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendChar")]
        public string StringInterpolation_WithChar()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${new string(EncodedSaltAsChars)}{new string(EncodedHashAsChars)}";
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendChar")]
        public string StringInterpolation_WithCharsConcat()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${new string(Concatenate(EncodedSaltAsChars, EncodedHashAsChars))}";
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendChar")]
        public string StringInterpolation_WithAllocConcat()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${ConcatenateToString(EncodedSaltAsChars, EncodedHashAsChars)}";
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendString")]
        public string StringInterpolation_WithString()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${salt}{hash}";
        }
    }
}
