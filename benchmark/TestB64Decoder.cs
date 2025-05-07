using System;
using System.Collections.Generic;
using BCryptNet.BenchMarks.DecodeB64;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    [MemoryDiagnoser]
    /*[RPlotExporter]*/
    [RankColumn]
    //[GcServer(true)]
    [Orderer(SummaryOrderPolicy.Declared)]
    [KeepBenchmarkFiles]
    [MarkdownExporterAttribute.GitHub]
    // [ReturnValueValidator(failOnError: true)]
    [IterationTime(500)]
    public class TestB64Decoder
    {
        public TestB64Decoder()
        {
            var salt = "DCq7YPn5Rq63x1Lad4cll.";
            var original = Convert.ToBase64String(DecodeB64Methods.DecodeBase64StandardUnSized(salt, 16));
            var exceptions = new List<Exception>();

            if (!Convert.ToBase64String(DecodeB64Methods.DecodeBase64StandardSized(salt, 16)).Equals(original))
                exceptions.Add(new Exception($"DecodeBase64StandardSized failed: {original} vs {Convert.ToBase64String(DecodeB64Methods.DecodeBase64StandardSized(salt, 16))}"));
            if (!Convert.ToBase64String(DecodeB64Methods.DecodeBase64StringCreateSpan(salt, 16)).Equals(original))
                exceptions.Add(new Exception($"DecodeBase64StringCreateSpan failed: {original} vs {Convert.ToBase64String(DecodeB64Methods.DecodeBase64StringCreateSpan(salt, 16))}"));
            if (!Convert.ToBase64String(DecodeB64Methods.DecodeBase64ToBytes(salt, 16)).Equals(original))
                exceptions.Add(new Exception($"DecodeBase64ToBytes failed: {original} vs {Convert.ToBase64String(DecodeB64Methods.DecodeBase64ToBytes(salt, 16))}"));

            Span<byte> saltBuffer = stackalloc byte[16];
            int written = DecodeB64Methods.DecodeBase64SpanBuffer(salt, saltBuffer);
            if (!Convert.ToBase64String(saltBuffer[..written].ToArray()).Equals(original))
                exceptions.Add(new Exception($"DecodeBase64SpanBuffer failed: {original} vs {Convert.ToBase64String(saltBuffer[..written].ToArray())}"));

            if (exceptions.Count > 0)
                throw new AggregateException(exceptions);
        }

        [Benchmark(Baseline = true)]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] UnsizedStringBuilderOriginal(string salt)
        {
            return DecodeB64Methods.DecodeBase64StandardUnSized(salt, 16);
        }

        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] SizedStringBuilderOriginal(string salt)
        {
            return DecodeB64Methods.DecodeBase64StandardSized(salt, 16);
        }

        [Benchmark]
        [Arguments("DCq7YPn5Rq63x1Lad4cll.")]
        [Arguments("HqWuK6/Ng6sg9gQzbLrgb.")]
        public byte[] StringCreateWithSpanAndBuffer(string salt)
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
        public byte[] DecodeBase64SpanBuffer(string salt)
        {
            Span<byte> saltBuffer = stackalloc byte[16];
            int written = DecodeB64Methods.DecodeBase64SpanBuffer(salt, saltBuffer);
            return saltBuffer[..written].ToArray();
        }
    }
}
