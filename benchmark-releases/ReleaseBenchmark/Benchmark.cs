using System;
// ReSharper disable once RedundantUsingDirective
using BCryptNet;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

namespace ReleaseBenchmark;

[MemoryDiagnoser]
[GcServer(true)]
[KeepBenchmarkFiles]
[MarkdownExporterAttribute.GitHub]
[ReturnValueValidator(failOnError: true)]
public abstract class Benchmark
{
    protected static Job BaseJob = Job.MediumRun;

    private const string Key = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
    private const string Salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
#if POSTV5
    private static ReadOnlySpan<char> KeySpan => Key.AsSpan();
    private static ReadOnlySpan<char> SaltSpan => Salt.AsSpan();
#endif

    [Benchmark]
    [BenchmarkCategory("HashSpan")]
    public string TestHashing()
    {
#if POSTV5 && NETCOREAPP
        Span<char> outputBuffer = stackalloc char[60];
        BCryptNet.BCrypt.HashPassword(KeySpan, SaltSpan, outputBuffer, out int outputBufferWritten);
        return new string(outputBuffer[..outputBufferWritten]);
        // return BCryptNet.BCrypt.HashPassword(KeySpan, SaltSpan);
#elif POSTV5 && !NETFRAMEWORK
        return BCryptNet.BCrypt.HashPassword(KeySpan, SaltSpan);
#elif POSTV5
        return BCryptNet.BCrypt.HashPassword(Key, Salt);
#else
        return BCrypt.Net.BCrypt.HashPassword(Key, Salt);
#endif
    }


}
