using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Core
{
    public class Program
    {
        public static void Main(string[] args)
        {
            const string password = "fancy";
            const string passwordHash = "$2a$04$mHManSTXI9OrvFGtT3Nsz.eyyGumdhnj/oRAGINntWjZ7D/rtupx2";

            Debug.Assert(BCrypt.Net.BCrypt.Verify(password, passwordHash));
        }
    }
}
