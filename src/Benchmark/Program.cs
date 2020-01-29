using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace BCrypt.Net.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<Benchmarks>();
            Console.ReadLine();
        }
    }

    [MemoryDiagnoser]
    public class Benchmarks
    {
        [Benchmark]
        public string GenerateSalt()
            => BCrypt.GenerateSalt(10);

        [Benchmark]
        public bool PasswordNeedsRehash()
            => BCrypt.PasswordNeedsRehash("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", 10);

        [Benchmark]
        [Arguments("")]
        [Arguments("abcdefghijklmnopqrstuvwxyz")]
        public string HashPassword(string value)
            => BCrypt.HashPassword(value, "$2a$06$DCq7YPn5Rq63x1Lad4cll.", true, HashType.SHA384);

        [Benchmark]
        [Arguments("", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO")]
        [Arguments("abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq")]
        public bool VerifyPassword(string text, string hash)
            => BCrypt.Verify(text, hash);
    }
}
