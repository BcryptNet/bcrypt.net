namespace DotNet2
{
    using BCrypt.Net;
    using System.Diagnostics;

    class Program
    {
        static void Main(string[] args)
        {
            const string password = "fancy";
            const string passwordHash = "$2a$04$mHManSTXI9OrvFGtT3Nsz.eyyGumdhnj/oRAGINntWjZ7D/rtupx2";

            Debug.Assert(BCrypt.Verify(password, passwordHash));
        }
    }
}
