using System;
using BCryptNet.BenchMarks.DecodeB64;
using BenchmarkDotNet.Attributes;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class TestB64Decoder
    {

        [Benchmark(Baseline = true)]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] DecodeBase64StandardUnSized(string salt)
        {
            return DecodeB64Methods.DecodeBase64StandardUnSized(salt, 16);
        }

        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] DecodeBase64StandardSized(string salt)
        {
            return DecodeB64Methods.DecodeBase64StandardSized(salt, 16);
        }

        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] DecodeBase64StringCreateSpan(string salt)
        {
            return DecodeB64Methods.DecodeBase64StringCreateSpan(salt, 16);
        }
        
        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] DecodeBase64ToBytes(string salt)
        {
           return DecodeB64Methods.DecodeBase64ToBytes(salt, 16);
        }

        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] DecodeBase64ToSpan(string salt)
        {
            Span<byte> saltBuffer = stackalloc byte[128 / 8];
            int written = DecodeB64Methods.DecodeBase64(salt, saltBuffer);
            return saltBuffer[..written].ToArray();
        }

    }
}
