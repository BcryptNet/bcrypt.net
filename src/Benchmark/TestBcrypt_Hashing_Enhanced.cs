using System.Collections.Generic;
using System.Linq;
using Benchmark._3._2._1;
using Benchmark._3._5.perfmerge_1;
using BenchmarkDotNet.Attributes;
#pragma warning disable 1591

namespace BCrypt.Net.Benchmarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class TestBcrypt_Hashing_Enhanced
    {
        public IEnumerable<object[]> Data()
        {
            yield return new object[] { "", "$2a$06$DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." };
            yield return new object[] { "", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye" };
            yield return new object[] { "", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW" };
            yield return new object[] { "", "$2a$12$k42ZFHFWqBp3vWli.nIn8u", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO" };
            yield return new object[] { "a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" };
            yield return new object[] { "a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V." };
            yield return new object[] { "a", "$2a$10$k87L/MF28Q673VKh8/cPi.", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u" };
            yield return new object[] { "a", "$2a$12$8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS" };
            yield return new object[] { "abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" };
            yield return new object[] { "abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm" };
            yield return new object[] { "abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi" };
            yield return new object[] { "abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q" };
            yield return new object[] { "abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" };
            yield return new object[] { "abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz." };
            yield return new object[] { "abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq" };
            yield return new object[] { "abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7Gpu", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG" };
            yield return new object[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" };
            yield return new object[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW" };
            yield return new object[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS" };
            yield return new object[] { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC" };
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhanced(string key, string salt, string hash)
        {
            string hashed = BaseLine.BCrypt.HashPassword(key, salt, enhancedEntropy: true);
            var validateHashCheck = BaseLine.BCrypt.EnhancedVerify(key, hashed);
            return hashed + validateHashCheck.ToString();
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhancedPerf1(string key, string salt, string hash)
        {
            string hashed = PerfMerge1.BCrypt.HashPassword(key, salt, enhancedEntropy: true);
            var validateHashCheck = PerfMerge1.BCrypt.EnhancedVerify(key, hashed);
            return hashed + validateHashCheck.ToString();
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhancedCurrent(string key, string salt, string hash)
        {
            string hashed = PerfMerge1.BCrypt.HashPassword(key, salt, enhancedEntropy: true);
            var validateHashCheck = PerfMerge1.BCrypt.EnhancedVerify(key, hashed);
            return hashed + validateHashCheck.ToString();

        }

    }
}
