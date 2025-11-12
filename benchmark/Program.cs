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
            var config = DefaultConfig.Instance
                    .AddJob(Job.Default.WithRuntime(CoreRuntime.Core80))
                    .AddJob(Job.Default.WithRuntime(CoreRuntime.Core90))
                    .AddJob(Job.Default.WithRuntime(CoreRuntime.Core10_0))
                    .AddJob(Job.Default.WithRuntime(ClrRuntime.Net481))
                ;
            BenchmarkSwitcher.FromAssemblies([typeof(Program).Assembly]).Run(args, config);
        }
    }
}
