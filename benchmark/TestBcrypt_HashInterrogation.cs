using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks._4._0._0;
using BenchmarkDotNet.Attributes;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class TestBcrypt_HashInterrogation
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
        public void InterrogateHashUsingParserV4(string hash)
        {
            version4.BCrypt.InterrogateHash(hash);
        }        
        
        [Benchmark()]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingParserCurrent(string hash)
        {
            BCrypt.InterrogateHash(hash);
        }
    }
}
