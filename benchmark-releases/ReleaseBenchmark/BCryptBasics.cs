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
                ("2.0.0", new Runtime[] {ClrRuntime.Net462, ClrRuntime.Net481}, false),
                ("2.1.4", [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0], false),
                ("3.5.0", [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0], false),
                ("4.0.3", [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0], false),
                (VersionInfo.BCryptVersion, [ClrRuntime.Net462, ClrRuntime.Net481, CoreRuntime.Core80, CoreRuntime.Core10_0],true)
            };

            foreach (var (version, runtimes, prerelease) in versions)
            {
                // var job = BaseJob.WithNuGet(new NuGetReferenceList
                // {
                //     new NuGetReference("BCrypt.Net-Next", version.Trim(), prerelease: prerelease)
                // });

                foreach (var runtime in runtimes)
                {
                    AddJob(BaseJob.WithRuntime(runtime).WithMsBuildArguments($"/p:BCryptVersion={version}"));
                }
            }
        }
    }

    [GlobalSetup]
    public void Setup()
    {
    }
}
