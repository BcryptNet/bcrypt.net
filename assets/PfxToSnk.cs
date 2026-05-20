using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class PfxToSnk
{
    static void Main(string[] args)
    {
        var cert = new X509Certificate2(args[0], args.Length > 1 ? args[1] : "",
            X509KeyStorageFlags.Exportable);
        var rsa = cert.GetRSAPrivateKey();
        var parameters = rsa.ExportParameters(true);

        // Re-import into RSACryptoServiceProvider to get the CSP blob
        var csp = new RSACryptoServiceProvider();
        csp.ImportParameters(parameters);
        var blob = csp.ExportCspBlob(true);

        File.WriteAllBytes(args[0].Replace(".pfx", ".snk"), blob);
        Console.WriteLine("Done. Written " + blob.Length + " bytes.");
    }
}
