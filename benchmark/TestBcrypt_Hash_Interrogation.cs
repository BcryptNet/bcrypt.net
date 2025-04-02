using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks._4._0._0;
using BCryptNet.BenchMarks._4._0._3;
using BCryptNet.BenchMarks.HashParser;
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
    public class TestBcrypt_Hash_Interrogation
    {
        [Benchmark(Baseline = true)]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingRegex(string hash)
        {
            BCryptBaseLine.BCrypt.InterrogateHash(hash);
        }

        [Benchmark()]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingParserV4(string hash)
        {
            BCryptV4.BCrypt.InterrogateHash(hash);
        }

        [Benchmark()]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingParserV403(string hash)
        {
            BCryptV403.BCrypt.InterrogateHash(hash);
        }        
        
        [Benchmark()]
        [Arguments("$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments( "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public void InterrogateHashUsingParserCurrent(string hash)
        {
            BCrypt.InterrogateHash(hash);
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
