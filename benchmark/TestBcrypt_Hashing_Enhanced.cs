using System;
using System.Collections.Generic;
using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks._3._5.perfmerge_1;
using BCryptNet.BenchMarks._4._0._0;
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
    public class TestBcryptHashingEnhanced
    {
        public IEnumerable<object[]> Data()
        {
            yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe"];
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhanced(string key, string salt)
        {
            return BCryptBaseLine.BCrypt.HashPassword(key, salt, enhancedEntropy: true);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhancedv3Perf(string key, string salt)
        {
            return BCrypt305PerfMerge1.BCrypt.HashPassword(key, salt, enhancedEntropy: true);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhancedv4Perf(string key, string salt)
        {
            return BCryptV4.BCrypt.HashPassword(key, salt, enhancedEntropy: true);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhancedCurrent(string key, string salt)
        {
            return  BCryptExtendedV2.HashPassword(key, salt);
        }

        private static readonly string Hmackey = Guid.NewGuid().ToString();

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateEnhancedNet8Plus(string key, string salt)
        {
            return BCryptExtendedV3.HashPassword(Hmackey, key, salt);
        }
    }
}
