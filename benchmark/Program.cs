using System;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Validators;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    class Program
    {
        static void Main(string[] args)
        {
            #if DEBUG
            BenchmarkRunner.Run<TestBcrypt_Hashing>(new DebugInProcessConfig().AddValidator(ExecutionValidator.FailOnError));
            // BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly)
            //     .Run(args, new DebugInProcessConfig()
            //         // .With(Job.Default.With(CoreRuntime.Latest))
            //         // .With(Job.Default.With(ClrRuntime.Net48))
            //         .AddValidator(ExecutionValidator.FailOnError));
            #else
            var config = DefaultConfig.Instance
                .With(Job.Default.With(CoreRuntime.Core60))
                .With(Job.Default.With(ClrRuntime.Net48));
            // BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);
            
            BenchmarkRunner.Run<TestBcrypt_Hashing>(config);
            BenchmarkRunner.Run<TestBcrypt_Hashing_Enhanced>(config);
            
            // Tests for testing in isolation
            BenchmarkRunner.Run<InterrogateHashBenchmarks>(config);
            BenchmarkRunner.Run<TestB64Decoder>(config);
            BenchmarkRunner.Run<TestB64Encoder>(config);
            BenchmarkRunner.Run<TestVariantsOnStringBuilding>(config);
            #endif

        }
    }
}
