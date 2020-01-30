using System.Text;
using Benchmark._3._2._1;
using Benchmark.HashParser;
using BenchmarkDotNet.Attributes;

#pragma warning disable 1591

namespace BCrypt.Net.Benchmarks
{
    [MemoryDiagnoser]
    [CategoriesColumn]
    [RPlotExporter, RankColumn]
    [ReturnValueValidator(failOnError: true)]
    public class TestVariantsOnStringBuilding
    {
        private readonly string bcryptMinorRevision = "a";
        private static readonly string hash = "TV4S6ytwfsfvkgY8jIucDrjc8deX1s.";
        private static readonly string salt = "DCq7YPn5Rq63x1Lad4cll.";

        private static readonly byte[] SaltBytes = BaseLine.BCrypt.DecodeBase64(salt, 16);
        private static readonly byte[] HashBytes = BaseLine.BCrypt.DecodeBase64(hash, 23);

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
        public string Original_StrBuilder_SinEncoding_AppendChar()
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
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized()
        {
            // Generate result string
            StringBuilder result = new StringBuilder(60);
            result.AppendFormat("$2{1}${0:00}$",  workFactor, bcryptMinorRevision);
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized_PRFmt()
        {
            var result = new StringBuilder(60);
            result.Append("$2").Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2")).Append('$');
            result.Append(EncodedSaltAsChars);
            result.Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendString")]
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized_FROMSTRING_PRFmt()
        {
            var result = new StringBuilder(60);
            result.Append("$2").Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2")).Append('$');
            result.Append(salt);
            result.Append(hash);

            return result.ToString();
        }


        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendChar")]
        public string StringInterpolation_WithChar()
        {
            return
                $"$2{bcryptMinorRevision}${workFactor:00}${new string(EncodedSaltAsChars)}{new string(EncodedHashAsChars)}";
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendString")]
        public string StringInterpolation_WithString()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${salt}{hash}";
        }
    }
}
