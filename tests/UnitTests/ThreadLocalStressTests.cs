using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BCryptNet.UnitTests;

/// <summary>
/// Stress tests to verify that the ThreadLocal&lt;uint[]&gt; reuse of _p and _s arrays
/// in BCryptBase.InitializeKey() is safe under concurrent usage.
/// </summary>
public class ThreadLocalStressTests
{
    // Use low work factor to keep tests fast while still exercising the code paths.
    private const int WorkFactor = 4;
    private static int ThreadCount => Math.Max(Environment.ProcessorCount * 2, 8);

    /// <summary>
    /// Hashes the same password on many threads simultaneously and verifies
    /// every result is a valid bcrypt hash that verifies correctly.
    /// Detects corruption in ThreadLocal arrays that would produce wrong hashes.
    /// </summary>
    [Fact]
    public void ConcurrentHashPassword_AllResultsVerify()
    {
        int threadCount = ThreadCount;
        const int iterationsPerThread = 20;
        const string password = "correcthorsebatterystaple";

        var errors = new ConcurrentBag<string>();

        Parallel.For(0, threadCount, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, threadIndex =>
        {
            for (int i = 0; i < iterationsPerThread; i++)
            {
                try
                {
                    string hash = BCrypt.HashPassword(password, WorkFactor);

                    if (!BCrypt.Verify(password, hash))
                    {
                        errors.Add($"Thread {threadIndex}, iteration {i}: Hash failed to verify. Hash={hash}");
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"Thread {threadIndex}, iteration {i}: Exception: {ex}");
                }
            }
        });

        Assert.Empty(errors);
    }

    /// <summary>
    /// Each thread hashes a unique password and verifies it, while also verifying
    /// it does NOT match other threads' passwords. Detects cross-thread data leakage
    /// where one thread's key schedule bleeds into another's result.
    /// </summary>
    [Fact]
    public void ConcurrentHashPassword_NoCrossThreadLeakage()
    {
        int threadCount = ThreadCount;
        const int iterationsPerThread = 10;

        var results = new ConcurrentDictionary<string, string>(); // password -> hash
        var errors = new ConcurrentBag<string>();

        Parallel.For(0, threadCount * iterationsPerThread,
            new ParallelOptions { MaxDegreeOfParallelism = threadCount },
            index =>
            {
                try
                {
                    string password = $"password-{index}-{Guid.NewGuid()}";
                    string hash = BCrypt.HashPassword(password, WorkFactor);

                    results[password] = hash;

                    if (!BCrypt.Verify(password, hash))
                    {
                        errors.Add($"Index {index}: Own password failed to verify");
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"Index {index}: Exception: {ex}");
                }
            });

        Assert.Empty(errors);

        // Cross-check: no password should verify against another password's hash
        var allPairs = results.ToArray();
        var crossErrors = new ConcurrentBag<string>();

        Parallel.For(0, Math.Min(allPairs.Length, 50), i =>
        {
            for (int j = i + 1; j < Math.Min(allPairs.Length, 50); j++)
            {
                if (BCrypt.Verify(allPairs[i].Key, allPairs[j].Value))
                {
                    crossErrors.Add($"Cross-thread leakage: password '{allPairs[i].Key}' verified against hash for '{allPairs[j].Key}'");
                }
            }
        });

        Assert.Empty(crossErrors);
    }

    /// <summary>
    /// Rapidly alternates between HashPassword and Verify on the same thread
    /// using Task continuations that may be scheduled on thread pool threads,
    /// exercising the ThreadLocal reuse when the same thread handles different operations.
    /// </summary>
    [Fact]
    public async Task RapidHashAndVerify_InterleavedOnThreadPool()
    {
        const int operationCount = 100;
        var errors = new ConcurrentBag<string>();

        var tasks = Enumerable.Range(0, operationCount).Select(async i =>
        {
            try
            {
                string password = $"rapid-{i}";
                string hash = await Task.Run(() => BCrypt.HashPassword(password, WorkFactor));
                bool verified = await Task.Run(() => BCrypt.Verify(password, hash));

                if (!verified)
                {
                    errors.Add($"Operation {i}: Hash/Verify mismatch on thread pool. Hash={hash}");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Operation {i}: Exception: {ex}");
            }
        });

        await Task.WhenAll(tasks);
        Assert.Empty(errors);
    }

    /// <summary>
    /// Tests that enhanced (SHA-384 pre-hashed) bcrypt also works correctly
    /// under concurrent ThreadLocal reuse.
    /// </summary>
    [Fact]
    public void ConcurrentEnhancedHashPassword_AllResultsVerify()
    {
        int threadCount = ThreadCount;
        const int iterationsPerThread = 10;
        const string password = "enhanced-stress-test-password";

        var errors = new ConcurrentBag<string>();

        Parallel.For(0, threadCount, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, threadIndex =>
        {
            for (int i = 0; i < iterationsPerThread; i++)
            {
                try
                {
                    string hash = BCryptExtendedV2.HashPassword(password, WorkFactor);

                    if (!BCryptExtendedV2.Verify(password, hash))
                    {
                        errors.Add($"Thread {threadIndex}, iteration {i}: Enhanced hash failed to verify");
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"Thread {threadIndex}, iteration {i}: Exception: {ex}");
                }
            }
        });

        Assert.Empty(errors);
    }

    /// <summary>
    /// Fires a burst of concurrent hashes, collects all results, then verifies
    /// them all in a second concurrent burst. This maximizes the chance of
    /// ThreadLocal array reuse across different logical operations.
    /// </summary>
    [Fact]
    public void BurstHashThenBurstVerify_AllCorrect()
    {
        const int count = 100;
        var passwords = Enumerable.Range(0, count).Select(i => $"burst-{i}").ToArray();
        var hashes = new string[count];
        var errors = new ConcurrentBag<string>();

        // Burst 1: hash all passwords concurrently
        Parallel.For(0, count, i =>
        {
            try
            {
                hashes[i] = BCrypt.HashPassword(passwords[i], WorkFactor);
            }
            catch (Exception ex)
            {
                errors.Add($"Hash phase, index {i}: {ex}");
            }
        });

        Assert.Empty(errors);

        // Burst 2: verify all concurrently
        Parallel.For(0, count, i =>
        {
            try
            {
                if (!BCrypt.Verify(passwords[i], hashes[i]))
                {
                    errors.Add($"Verify phase, index {i}: failed. Hash={hashes[i]}");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Verify phase, index {i}: {ex}");
            }
        });

        Assert.Empty(errors);
    }

    /// <summary>
    /// Saturates a small thread pool to force maximum ThreadLocal reuse.
    /// Uses ThreadPool.SetMinThreads to control thread count, then fires
    /// more work items than threads to ensure arrays are reused.
    /// </summary>
    [Fact]
    public async Task ThreadPoolSaturation_ForcesThreadLocalReuse()
    {
        const int workItemCount = 200;
        var errors = new ConcurrentBag<string>();
        using var barrier = new CountdownEvent(workItemCount);

        var tasks = new Task[workItemCount];
        for (int i = 0; i < workItemCount; i++)
        {
            int index = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    string password = $"saturation-{index}";
                    string hash = BCrypt.HashPassword(password, WorkFactor);

                    if (!BCrypt.Verify(password, hash))
                    {
                        errors.Add($"Work item {index}: verification failed");
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"Work item {index}: {ex}");
                }
                finally
                {
                    barrier.Signal();
                }
            }, TestContext.Current.CancellationToken);
        }

        barrier.Wait(TimeSpan.FromMinutes(5), TestContext.Current.CancellationToken);
        await Task.WhenAll(tasks);
        Assert.Empty(errors);
    }
}
