using System;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

namespace ReleaseBenchmark;

[MemoryDiagnoser]
[RPlotExporter]
[RankColumn]
[GcServer(true)]
[KeepBenchmarkFiles]
[MarkdownExporterAttribute.GitHub]
[ReturnValueValidator(failOnError: true)]
public abstract class Benchmark
{
    protected static Job BaseJob = Job.Default;

    public static IEnumerable<object[]> Data()
    {
        yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"];
        yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"];
    }

    private const string Key = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
    private const string Salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
#if POSTV5
    private ReadOnlySpan<char> KeySpan => Key.AsSpan();
    private ReadOnlySpan<char> SaltSpan => Salt.AsSpan();
#endif

//     [Benchmark(Baseline = true)]
//     [BenchmarkCategory("Hash")]
//     [ArgumentsSource(nameof(Data))]
//     public string TestHashValidate(string key, string salt, string hash)
//     {
// #if POSTV5
//         return BCryptNet.BCrypt.HashPassword(key, salt);
// #else
//         return BCrypt.Net.BCrypt.HashPassword(key, salt);
// #endif
//     }

    [Benchmark]
    [BenchmarkCategory("HashSpan")]
    public string TestSpanBasedHashing()
    {
#if POSTV5 && NETCOREAPP
        return BCryptNet.BCrypt.HashPassword(KeySpan, SaltSpan);
#elif POSTV5
        return BCryptNet.BCrypt.HashPassword(Key, Salt);
#else
        return BCrypt.Net.BCrypt.HashPassword(Key, Salt);
#endif
    }


}
