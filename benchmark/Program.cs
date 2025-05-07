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
            BenchmarkRunner.Run<TestB64Decoder>(new DebugInProcessConfig().AddValidator(ExecutionValidator.FailOnError));
            #else
            var config = DefaultConfig.Instance
                .With(Job.Default.With(CoreRuntime.Core90))
                ;

            // BenchmarkRunner.Run<TestEnhancedV3_Hmac>(config);
            // BenchmarkRunner.Run<TestBcrypt_Hashing>(config);
            // BenchmarkRunner.Run<TestBcrypt_Hashing_Validation>(config);
            // BenchmarkRunner.Run<TestBcryptHashingEnhanced>(config);
            // BenchmarkRunner.Run<TestBcryptHashingEnhancedValidation>(config);
            // //
            // // // Tests for testing in isolation
            // BenchmarkRunner.Run<TestBcrypt_Hash_Interrogation>(config);
            BenchmarkRunner.Run<TestB64Decoder>(config);
            BenchmarkRunner.Run<TestB64Encoder>(config);
            BenchmarkRunner.Run<TestVariantsOnStringBuilding>(config);
            #endif

        }
    }
}
