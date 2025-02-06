using System;

namespace ExampleConsoleApp;

using BCryptNet;

internal class Program
{
    public static void Main(string[] args)
    {
        var hash = BCrypt.HashPassword("password");
        Console.WriteLine($"Password hash: {hash}");
        Console.WriteLine("Validating Password");
        var isValid = BCrypt.Verify("password", hash);
        Console.WriteLine($"Is valid: {isValid}");

        var hashInformation = BCrypt.InterrogateHash(hash);
        Console.WriteLine(hashInformation);

        Console.WriteLine("Finished; hit enter to exit");
        Console.ReadLine();
    }
}
