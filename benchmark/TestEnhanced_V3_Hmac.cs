// /*
// The MIT License (MIT)
// Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
// Copyright (c) 2013 Ryan D. Emerle (.Net port)
// Copyright (c) 2016/2025 Chris McKee (.Net-core port / patches / new features)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
// merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
// */

using System;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

namespace BCryptNet.BenchMarks;

[MemoryDiagnoser]
/*[RPlotExporter]*/
[RankColumn]
//[GcServer(true)]
[Orderer(SummaryOrderPolicy.Declared)]
[KeepBenchmarkFiles]
[MarkdownExporterAttribute.GitHub]
// [ReturnValueValidator(failOnError: true)]
[IterationTime(500)]
public class TestEnhancedV3_Hmac
{
    // Store the strings as fields
    private const string HmacKeyString = "SuperSecureHMACKey";
    private const string InputKeyString = "SensitiveDataToHash";
    private ReadOnlySpan<char> HmacKey => HmacKeyString.AsSpan();
    private ReadOnlySpan<char> InputKey => InputKeyString.AsSpan();

    private const HashType hashType = HashType.SHA256;
    private const char BcryptMinorRevision = 'a';

    [Benchmark(Baseline = true)]
    public byte[] OldMethod() => EnhancedHashOld(HmacKey, InputKey, hashType, BcryptMinorRevision).ToArray();

    [Benchmark]
    public byte[] NewMethod() => EnhancedHash(HmacKey, InputKey, hashType, BcryptMinorRevision);

    private static Span<byte> EnhancedHashOld(ReadOnlySpan<char> hmacKey, ReadOnlySpan<char> inputKey, HashType hashType, char bcryptMinorRevision)
    {
        switch (hashType)
        {
            case HashType.SHA256:
                using (var sha = new HMACSHA3_256(Encoding.UTF8.GetBytes(hmacKey.ToString())))
                    return Encoding.UTF8.GetBytes(Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(inputKey.ToString()))) +
                                                  (bcryptMinorRevision >= 'a' ? "\0" : ""));
            case HashType.SHA384:
                using (var sha = new HMACSHA3_384(Encoding.UTF8.GetBytes(hmacKey.ToString())))
                    return Encoding.UTF8.GetBytes(Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(inputKey.ToString()))) +
                                                  (bcryptMinorRevision >= 'a' ? "\0" : ""));
            case HashType.SHA512:
                using (var sha = new HMACSHA3_512(Encoding.UTF8.GetBytes(hmacKey.ToString())))
                    return Encoding.UTF8.GetBytes(Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(inputKey.ToString()))) +
                                                  (bcryptMinorRevision >= 'a' ? "\0" : ""));
            default:
                throw new ArgumentOutOfRangeException(nameof(hashType), hashType, null);
        }
    }

    private static byte[] EnhancedHash(ReadOnlySpan<char> hmacKey, ReadOnlySpan<char> inputKey, HashType hashType, char bcryptMinorRevision)
    {
        ushort hashLen = hashType switch
        {
            HashType.SHA256 => 32,
            HashType.SHA384 => 48,
            HashType.SHA512 => 64,
            _ => throw new ArgumentOutOfRangeException(nameof(hashType))
        };

        Span<byte> keyBytes = stackalloc byte[Encoding.UTF8.GetMaxByteCount(hmacKey.Length)];
        Span<byte> dataBytes = stackalloc byte[Encoding.UTF8.GetMaxByteCount(inputKey.Length)];
        Span<byte> hash = stackalloc byte[hashLen];

        int keyByteLen = Encoding.UTF8.GetBytes(hmacKey, keyBytes);
        int dataByteLen = Encoding.UTF8.GetBytes(inputKey, dataBytes);

        bool success = hashType switch
        {
            HashType.SHA256 => HMACSHA3_256.TryHashData(keyBytes[..keyByteLen], dataBytes[..dataByteLen], hash, out int len) && len == 32,
            HashType.SHA384 => HMACSHA3_384.TryHashData(keyBytes[..keyByteLen], dataBytes[..dataByteLen], hash, out int len) && len == 48,
            HashType.SHA512 => HMACSHA3_512.TryHashData(keyBytes[..keyByteLen], dataBytes[..dataByteLen], hash, out int len) && len == 64,
            _ => throw new ArgumentOutOfRangeException(nameof(hashType))
        };

        if (!success)
            throw new Exception($"HMAC-{hashType} failed");

        Span<char> base64Chars = stackalloc char[(hashLen + 2) / 3 * 4];
        if (!Convert.TryToBase64Chars(hash, base64Chars, out int base64Len))
            throw new Exception("Base64 encoding failed in EnhancedHash");

        Span<char> finalBase64 = stackalloc char[base64Len + (bcryptMinorRevision >= 'a' ? 1 : 0)];
        base64Chars[..base64Len].CopyTo(finalBase64);
        if (bcryptMinorRevision >= 'a') finalBase64[base64Len] = '\0';

        Span<byte> utf8Buffer = stackalloc byte[Encoding.UTF8.GetMaxByteCount(finalBase64.Length)];
        int utf8Len = Encoding.UTF8.GetBytes(finalBase64, utf8Buffer);

        return utf8Buffer[..utf8Len].ToArray();
    }

    public enum HashType
    {
        None,
        SHA256,
        SHA384,
        SHA512
    }
}
