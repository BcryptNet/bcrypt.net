using Benchmark.HashParser;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

#pragma warning disable 1591

namespace BCrypt.Net.Benchmarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class TestB64Decoder
    {

        [Benchmark(Baseline = true)]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public void DecodeBase64StandardUnSized(string salt)
        {
            var decoded = DecodeB64Methods.DecodeBase64StandardUnSized(salt, 16);
        }

        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public void DecodeBase64StandardSized(string salt)
        {
            var decoded = DecodeB64Methods.DecodeBase64StandardSized(salt, 16);
        }

#if NET2_1
        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public void DecodeBase64StringCreateSpan(string salt)
        {
            var decoded = DecodeB64Methods.DecodeBase64StringCreateSpan(salt, 16);
        }
#endif
        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public void DecodeBase64ToBytes(string salt)
        {
            var decoded = DecodeB64Methods.DecodeBase64ToBytes(salt, 16);
        }

    }
}
