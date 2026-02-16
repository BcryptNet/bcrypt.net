using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;

namespace ReleaseBenchmark;

[Config(typeof(Config))]
public class BCryptBasics : Benchmark
{
    private class Config : ManualConfig
    {
        public Config()
        {
            var versions = new[]
            {
                ("2.0.0", new Runtime[] {ClrRuntime.Net462, ClrRuntime.Net481}),
                ("2.1.4", [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0]),
                ("3.5.0", [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0]),
                ("4.0.3", [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0]),
                (VersionInfo.BCryptVersion, [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0])
            };

            foreach (var (version, runtimes) in versions)
            {
                foreach (var runtime in runtimes)
                {
                    AddJob(BaseJob.WithRuntime(runtime).WithMsBuildArguments($"/p:BCryptVersion={version}"));
                }
            }
        }
    }
}
