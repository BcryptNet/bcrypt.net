using System;
// ReSharper disable once RedundantUsingDirective
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Jobs;

namespace ReleaseBenchmark;

[MemoryDiagnoser]
[GcServer(true)]
[KeepBenchmarkFiles]
[MarkdownExporterAttribute.GitHub]
public abstract class Benchmark
{
    protected static Job BaseJob = Job.MediumRun;
    private readonly Consumer _consumer = new();

    private const string Key = "~!@#$%^&*()      ~!@#$%^&*()PNBFRD";
    private const string Salt = "$2a$12$WApznUOJfkEGSmYRfnkrPO";
#if POSTV5
    private static ReadOnlySpan<char> KeySpan => Key.AsSpan();
    private static ReadOnlySpan<char> SaltSpan => Salt.AsSpan();
#endif

    [Benchmark]
    [BenchmarkCategory("HashSpan")]
    public void TestHashing()
    {
#if POSTV5 && NETCOREAPP
        Span<char> outputBuffer = stackalloc char[60];
        BCryptNet.BCrypt.HashPassword(KeySpan, SaltSpan, outputBuffer, out int outputBufferWritten);
        _consumer.Consume(outputBufferWritten);
        if (outputBufferWritten > 0)
        {
            _consumer.Consume(outputBuffer[0]);
        }
#elif POSTV5 && NET48_OR_GREATER
        var hash = BCryptNet.BCrypt.HashPassword(KeySpan, SaltSpan);
        _consumer.Consume(hash);
#elif POSTV5 && NET462
        var hash = BCryptNet.BCrypt.HashPassword(Key, Salt);
        _consumer.Consume(hash);
#else
        var hash = BCrypt.Net.BCrypt.HashPassword(Key, Salt);
        _consumer.Consume(hash);
#endif
    }


}
