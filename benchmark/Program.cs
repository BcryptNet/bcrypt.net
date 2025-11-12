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
        static void Main(string[] args) => BenchmarkSwitcher.FromAssemblies(new[] { typeof(Program).Assembly }).Run(args);
//         static void Main(string[] args)
//         {
//             #if DEBUG
//             BenchmarkRunner.Run<TestBcrypt_Hashing>(new DebugInProcessConfig().AddValidator(ExecutionValidator.FailOnError));
//             #else
//             var config = DefaultConfig.Instance
//                  .AddJob(Job.Default.WithRuntime(CoreRuntime.Core90))
//                  .AddJob(Job.Default.WithRuntime(CoreRuntime.Core10_0))
//                  .AddJob(Job.Default.WithRuntime(ClrRuntime.Net481))
//                 ;
// #if NET5_0_OR_GREATER
//             BenchmarkRunner.Run<TestEnhancedV3_Hmac>(config);
// #endif
//             BenchmarkRunner.Run<TestBcrypt_Hashing>(config);
//             BenchmarkRunner.Run<TestBcrypt_Hashing_Validation>(config);
//             BenchmarkRunner.Run<TestBcryptHashingEnhanced>(config);
//             BenchmarkRunner.Run<TestBcryptHashingEnhancedValidation>(config);
//             BenchmarkRunner.Run<TestBcrypt_Hash_Interrogation>(config);
// #if NET5_0_OR_GREATER
//             BenchmarkRunner.Run<TestB64Decoder>(config);
//             BenchmarkRunner.Run<TestB64Encoder>(config);
// #endif
//             BenchmarkRunner.Run<TestVariantsOnStringBuilding>(config);
//             #endif
//
//         }
    }
}
