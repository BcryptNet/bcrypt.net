using System;

namespace ExampleConsoleApp;

using BCryptNet;

internal class Program
{
    public static void Main(string[] args)
    {
        var hash = BCryptExtendedV3.HashPassword(HmacKey.FromString("test"), "password", new BCryptOptions(preHash: PreHash.HmacSha3(HashType.SHA512)));
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
