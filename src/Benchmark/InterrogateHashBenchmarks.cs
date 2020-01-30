using Benchmark._3._2._1;
using Benchmark.HashParser;
using BenchmarkDotNet.Attributes;
#pragma warning disable 1591

namespace BCrypt.Net.Benchmarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class InterrogateHashBenchmarks
    {

        [Benchmark(Baseline = true)]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingRegex(string hash)
        {
            BaseLine.BCrypt.InterrogateHash(hash);
        }

        [Benchmark()]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingParser(string hash)
        {
            Decoder.GetHashInformation(hash);
        }

    }
}
