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
    public class TestB64Encoder
    {
        private static readonly byte[] SaltBytes = BCryptBaseLine.BCrypt.DecodeBase64("sGBxdT2q8Qd84NyZEkwTY.", 16);

        [Benchmark(Baseline = true)]
        public void EncodeBase64Unsized()
        {
            EncodeB64Methods.EncodeBase64Unsized(SaltBytes, 16);
        }

        [Benchmark]
        public void EncodeBase64Sized()
        {
            EncodeB64Methods.EncodeBase64Sized(SaltBytes, 16);
        }

        [Benchmark]
        public void EncodeBase64AsBytes()
        {
            EncodeB64Methods.EncodeBase64AsBytes(SaltBytes, 16);
        }

        [Benchmark]
        public void EncodeBase64StackAlloc()
        {
            EncodeB64Methods.EncodeBase64StackAlloc(SaltBytes, 16);
        }

        [Benchmark]
        public void EncodeBase64HeapSpanAlloc()
        {
            EncodeB64Methods.EncodeBase64HeapAlloc(SaltBytes, 16);
        }
    }
}
