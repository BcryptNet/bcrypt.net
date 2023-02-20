using Benchmark._3._2._1;
using Benchmark.HashParser;
using BenchmarkDotNet.Attributes;

#pragma warning disable 1591

namespace nBCrypt.Benchmarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class TestB64Encoder
    {
        private static readonly byte[] SaltBytes = BaseLine.BCrypt.DecodeBase64("sGBxdT2q8Qd84NyZEkwTY.", 16);

        [Benchmark(Baseline = true)]
        public void EncodeBase64Unsized()
        {
            var decoded = EncodeB64Methods.EncodeBase64Unsized(SaltBytes, 16);
        }

        [Benchmark]
        public void EncodeBase64Sized()
        {
            var decoded = EncodeB64Methods.EncodeBase64Sized(SaltBytes, 16);
        }

        [Benchmark]
        public void EncodeBase64AsBytes()
        {
            var decoded = EncodeB64Methods.EncodeBase64AsBytes(SaltBytes, 16);
        }
    }
}