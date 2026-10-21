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

#if NET8_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace BCryptNet;

/// <summary>
/// Pre-hash family applied to the password before it is passed to bcrypt.
/// </summary>
public enum PreHashScheme
{
    /// <summary>Plain bcrypt; the password is used as-is (subject to the 72-byte limit).</summary>
    None = 0,

    /// <summary>base64(SHA2(password)), as produced by <see cref="BCryptExtendedV2"/>.</summary>
    Sha2 = 1,

    /// <summary>base64(HMAC-SHA3(key, password)), as produced by <c>BCryptExtendedV3</c>. Requires an <see cref="HmacKey"/>.</summary>
    HmacSha3 = 2
}

/// <summary>
/// Identifies how a password is pre-hashed before bcrypt: the scheme and its digest size.
/// </summary>
/// <remarks>
/// <para>Holds no key material; HMAC keys are always passed separately as an <see cref="HmacKey"/>.</para>
/// <para><c>default(PreHash)</c> is <see cref="None"/> (plain bcrypt).</para>
/// <para>
/// Hashes produced by every scheme share the same <c>$2x$</c> format, so the scheme can't be read back from a hash;
/// it has to be recorded or configured alongside it.
/// </para>
/// </remarks>
public readonly struct PreHash : IEquatable<PreHash>
{
    // Meaningless when Scheme is None; HashType normalises it away
    private readonly HashType _hashType;

    private PreHash(PreHashScheme scheme, HashType hashType)
    {
        if (hashType is < HashType.SHA256 or > HashType.SHA512)
        {
            throw new ArgumentOutOfRangeException(nameof(hashType), hashType, "The pre-hash digest must be SHA256, SHA384 or SHA512");
        }

        Scheme = scheme;
        _hashType = hashType;
    }

    /// <summary>
    /// Plain bcrypt, no pre-hashing.
    /// </summary>
    public static PreHash None => default;

    /// <summary>
    /// SHA2 pre-hashing (<see cref="BCryptExtendedV2"/>).
    /// </summary>
    /// <param name="hashType">Digest size (default SHA384).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="hashType"/> is not SHA256, SHA384 or SHA512.</exception>
    public static PreHash Sha2(HashType hashType = HashType.SHA384) => new(PreHashScheme.Sha2, hashType);

    /// <summary>
    /// HMAC-SHA3 pre-hashing (<c>BCryptExtendedV3</c>); requires an <see cref="HmacKey"/>.
    /// </summary>
    /// <param name="hashType">Digest size (default SHA384, i.e. HMAC-SHA3-384).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="hashType"/> is not SHA256, SHA384 or SHA512.</exception>
    public static PreHash HmacSha3(HashType hashType = HashType.SHA384) => new(PreHashScheme.HmacSha3, hashType);

    /// <summary>
    /// The pre-hash family.
    /// </summary>
    public PreHashScheme Scheme { get; }

    /// <summary>
    /// The digest size, or <see cref="BCryptNet.HashType.None"/> for plain bcrypt.
    /// </summary>
    public HashType HashType => Scheme == PreHashScheme.None ? HashType.None : _hashType;

    /// <summary>
    /// Whether hashing with this scheme needs an <see cref="HmacKey"/>.
    /// </summary>
    public bool RequiresKey => Scheme == PreHashScheme.HmacSha3;

    /// <summary>
    /// Whether this scheme can run on the current platform. SHA3 needs .NET 8+ and OS support
    /// (Windows 11 build 25324+, or OpenSSL 1.1.1+ on Linux; not available on macOS).
    /// </summary>
    public bool IsSupported => Scheme switch
    {
#if NET8_0_OR_GREATER
        PreHashScheme.HmacSha3 => _hashType switch
        {
            HashType.SHA256 => HMACSHA3_256.IsSupported,
            HashType.SHA384 => HMACSHA3_384.IsSupported,
            _ => HMACSHA3_512.IsSupported
        },
#else
        PreHashScheme.HmacSha3 => false,
#endif
        _ => true
    };

    /// <inheritdoc />
    public bool Equals(PreHash other) => Scheme == other.Scheme && HashType == other.HashType;

    /// <inheritdoc />
    public override bool Equals(object obj) => obj is PreHash other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => ((int)Scheme * 397) ^ ((int)HashType + 2);

    /// <inheritdoc />
    public override string ToString() => Scheme == PreHashScheme.None ? "None" : $"{Scheme}-{_hashType}";

    /// <summary>Equality operator.</summary>
    public static bool operator ==(PreHash left, PreHash right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(PreHash left, PreHash right) => !left.Equals(right);
}
