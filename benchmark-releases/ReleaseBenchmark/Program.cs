using BenchmarkDotNet.Running;

public class Program
{
    public static void Main(string[] args) =>
        BenchmarkSwitcher.FromAssemblies([typeof(Program).Assembly]).Run(args);
}
