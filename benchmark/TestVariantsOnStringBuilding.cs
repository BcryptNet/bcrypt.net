using System.Globalization;
using System.Text;
using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks.EncodeB64;
using BenchmarkDotNet.Attributes;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    [MemoryDiagnoser]
    [CategoriesColumn]
    [RPlotExporter, RankColumn]
    [ReturnValueValidator(failOnError: true)]
    [KeepBenchmarkFiles]
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
            result.AppendFormat("$2{1}${0:00}$", workFactor, bcryptMinorRevision);
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
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized_PRFmt_MoreChar()
        {
            var result = new StringBuilder(60);
            result.Append('$').Append('2').Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2", CultureInfo.InvariantCulture)).Append('$')
                .Append(EncodedSaltAsChars)
                .Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendChar")]
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized_PRFmt_MoreString()
        {
            var result = new StringBuilder(60);
            result.Append("$2").Append(bcryptMinorRevision).Append("$").Append(workFactor.ToString("D2")).Append("$")
                .Append(EncodedSaltAsChars)
                .Append(EncodedHashAsChars);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendString")]
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized_PRFmt_StringNotChar()
        {
            var result = new StringBuilder(60);
            result.Append("$2").Append(bcryptMinorRevision).Append("$").Append(workFactor.ToString("D2")).Append("$");
            result.Append(salt);
            result.Append(hash);

            return result.ToString();
        }

        [Benchmark]
        [BenchmarkCategory("StringAppend", "AppendString")]
        public string Original_StrBuilder_SinEncoding_AppendChar_Sized_FROMSTRING_PRFmt_plusfmt()
        {
            var result = new StringBuilder(60);
            result.Append("$2")
                .Append(bcryptMinorRevision)
                .Append("$")
                .Append($"{workFactor:00}")
                .Append("$")
                .Append(salt)
                .Append(hash);

            return result.ToString();
        }

        public static char[] Concatenate(char[] array1, char[] array2)
        {
            char[] result = new char[array1.Length + array2.Length];
            array1.CopyTo(result, 0);
            array2.CopyTo(result, array1.Length);
            return result;
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendChar")]
        public string StringInterpolation_WithChar()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${new string(EncodedSaltAsChars)}{new string(EncodedHashAsChars)}";
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendChar")]
        public string StringInterpolation_WithCharMerged()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${new string(Concatenate(EncodedSaltAsChars, EncodedHashAsChars))}";
        }

        [Benchmark]
        [BenchmarkCategory("StringFmt", "AppendString")]
        public string StringInterpolation_WithString()
        {
            return $"$2{bcryptMinorRevision}${workFactor:00}${salt}{hash}";
        }
    }
}
