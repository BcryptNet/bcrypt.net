using BenchmarkDotNet.Running;

namespace ReleaseBenchmark;

public class Program
{
    public static void Main(string[] args) =>
        BenchmarkSwitcher.FromAssemblies([typeof(Program).Assembly]).Run(args);
}
