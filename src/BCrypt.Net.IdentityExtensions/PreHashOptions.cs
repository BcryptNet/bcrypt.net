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

using System.Text;

namespace BCryptNet.IdentityExtensions;

/// <summary>
/// A configuration-bindable pre-hash scheme, e.g. <c>{ "Scheme": "HmacSha3", "Digest": "SHA384", "HmacKey": "..." }</c>.
/// </summary>
public sealed record PreHashOptions
{
    /// <summary>
    /// Pre-hash family (default: <see cref="PreHashScheme.None"/>, plain bcrypt).
    /// </summary>
    public PreHashScheme Scheme { get; set; } = PreHashScheme.None;

    /// <summary>
    /// Digest size (default SHA384); ignored for plain bcrypt.
    /// </summary>
    public HashType Digest { get; set; } = HashType.SHA384;

    /// <summary>
    /// HMAC key text, UTF-8 encoded. Required for <see cref="PreHashScheme.HmacSha3"/>, otherwise must be unset.
    /// Excluded from <see cref="ToString"/>.
    /// </summary>
    public string HmacKey { get; set; }

    /// <summary>
    /// Converts to the library's <see cref="PreHash"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when <see cref="Scheme"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="Digest"/> is not SHA256, SHA384 or SHA512.</exception>
    public PreHash ToPreHash() => Scheme switch
    {
        PreHashScheme.None => PreHash.None,
        PreHashScheme.Sha2 => PreHash.Sha2(Digest),
        PreHashScheme.HmacSha3 => PreHash.HmacSha3(Digest),
        _ => throw new InvalidOperationException($"Unknown pre-hash scheme {Scheme}")
    };

    // Redacts HmacKey
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Scheme = ").Append(Scheme)
            .Append(", Digest = ").Append(Digest)
            .Append(", HmacKey = ").Append(HmacKey is null ? "null" : "***");
        return true;
    }
}
