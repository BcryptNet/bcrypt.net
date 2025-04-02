using System;
using System.Collections.Generic;
using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks._3._5.perfmerge_1;
using BCryptNet.BenchMarks._4._0._0;
using BCryptNet.BenchMarks._4._0._3;
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
    // [ReturnValueValidator(failOnError: true)]
    public class TestBcrypt_Hashing
    {
        public IEnumerable<object[]> Data()
        {
            yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"];
            yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"];
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidate(string key, string salt, string hash)
        {
            return BCryptBaseLine.BCrypt.HashPassword(key, salt, enhancedEntropy: false);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidatePerf1(string key, string salt, string hash)
        {
            return BCrypt305PerfMerge1.BCrypt.HashPassword(key, salt, enhancedEntropy: false);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateV4(string key, string salt, string hash)
        {
            return BCryptV4.BCrypt.HashPassword(key, salt);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateV403(string key, string salt, string hash)
        {
            return BCryptV403.BCrypt.HashPassword(key, salt);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateCurrent(string key, string salt, string hash)
        {
            return BCrypt.HashPassword(key, salt);
        }
    }
}
