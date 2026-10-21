// /*
// The MIT License (MIT)
// Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
// Copyright (c) 2013 Ryan D. Emerle (.Net port)
// Copyright (c) 2016/2026 Chris McKee (.Net-core port / patches / new features)
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

namespace BCryptNet.IdentityExtensions;

/// <summary>
/// Prefixes a pre-hashed bcrypt hash with its scheme, e.g. <c>$bcnet-sha2-384$2b$12$...</c>. Plain bcrypt is untagged.
/// </summary>
/// <remarks>
/// Without it, a SHA2 hash verified as plain bcrypt accepts base64(SHA2(password)) as the password.
/// </remarks>
internal static class SchemeTag
{
    private const string Prefix = "$bcnet-";

    private static readonly PreHash[] Tagged =
    {
        PreHash.Sha2(HashType.SHA256), PreHash.Sha2(HashType.SHA384), PreHash.Sha2(HashType.SHA512),
        PreHash.HmacSha3(HashType.SHA256), PreHash.HmacSha3(HashType.SHA384), PreHash.HmacSha3(HashType.SHA512)
    };

    internal static string Apply(PreHash preHash, string hash) =>
        preHash.Scheme == PreHashScheme.None ? hash : string.Concat(Prefix, Name(preHash), hash);

    /// <returns><c>false</c> if the tag is malformed or unknown.</returns>
    internal static bool TryParse(string stored, out PreHash preHash, out string hash)
    {
        preHash = PreHash.None;
        hash = stored;

        if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
            return true;

        int end = stored.IndexOf('$', Prefix.Length);
        if (end < 0)
            return false;

        var name = stored.AsSpan(Prefix.Length, end - Prefix.Length);
        foreach (var candidate in Tagged)
        {
            if (name.SequenceEqual(Name(candidate)))
            {
                preHash = candidate;
                hash = stored[end..];
                return true;
            }
        }

        return false;
    }

    private static string Name(PreHash preHash)
    {
        string scheme = preHash.Scheme switch
        {
            PreHashScheme.Sha2 => "sha2",
            PreHashScheme.HmacSha3 => "hmac-sha3",
            _ => throw new InvalidOperationException($"Pre-hash {preHash} is not tagged")
        };
        string digest = preHash.HashType switch
        {
            HashType.SHA256 => "256",
            HashType.SHA384 => "384",
            HashType.SHA512 => "512",
            _ => throw new InvalidOperationException($"Pre-hash {preHash} is not tagged")
        };
        return $"{scheme}-{digest}";
    }
}
