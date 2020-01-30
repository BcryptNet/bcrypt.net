using System;
using BenchmarkDotNet.Running;
#pragma warning disable 1591

namespace BCrypt.Net.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<InterrogateHashBenchmarks>();
            BenchmarkRunner.Run<TestB64Decoder>();
            BenchmarkRunner.Run<TestB64Encoder>();
            BenchmarkRunner.Run<TestVariantsOnStringBuilding>();

            Console.WriteLine("Finished");
            Console.ReadLine();
        }
    }
}
