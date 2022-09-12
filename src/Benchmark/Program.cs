using System;
using BenchmarkDotNet.Running;
#pragma warning disable 1591

namespace nBCrypt.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<TestBcrypt_Hashing>();
            BenchmarkRunner.Run<TestBcrypt_Hashing_Enhanced>();

            // Tests for testing in isolation
            //BenchmarkRunner.Run<InterrogateHashBenchmarks>();
            //BenchmarkRunner.Run<TestB64Decoder>();
            //BenchmarkRunner.Run<TestB64Encoder>();
            //BenchmarkRunner.Run<TestVariantsOnStringBuilding>();

            Console.WriteLine("Finished");
            Console.ReadLine();
        }
    }
}