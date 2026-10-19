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

namespace BCryptNet;

/// <summary>
/// Per-call hashing policy (work factor, long-password handling and pre-hash algorithm).
/// </summary>
/// <remarks>
/// <para>
/// This is a small immutable value type so passing it costs no heap allocation. It deliberately holds
/// no secret material: passwords and HMAC keys are always separate parameters.
/// </para>
/// <para>
/// <c>default(BCryptOptions)</c> is valid and equivalent to the library defaults
/// (work factor <see cref="BCryptCore.DefaultRounds"/>, <see cref="LongPasswordHandling.Throw"/>,
/// and the calling class's default pre-hash).
/// </para>
/// </remarks>
public readonly struct BCryptOptions : IEquatable<BCryptOptions>
{
    // 0 means "not set, use the default" so default(BCryptOptions) is valid. An explicit 0 is rejected by the
    // constructor, so a caller passing 0 by mistake gets an exception rather than silently getting the default.
    private readonly int _workFactor;

    /// <summary>
    /// Creates a new set of options.
    /// </summary>
    /// <param name="workFactor">The log2 of the number of rounds of hashing to apply (4-31), or <c>null</c> for the default.
    /// Ignored when an explicit salt is supplied, as the salt carries its own work factor.</param>
    /// <param name="longPasswordHandling">Policy for passwords exceeding bcrypt's 72-byte limit.
    /// Pre-hashed (<see cref="BCryptExtendedV2"/> / V3) passwords are never subject to the limit, so there it only applies
    /// when <c>ValidateAndUpgradeHash</c> verifies a plain bcrypt hash being migrated.</param>
    /// <param name="preHash">Pre-hash algorithm for the extended (V2/V3) schemes; <c>null</c> uses the class default.
    /// Must be <c>null</c> or <see cref="HashType.None"/> for <see cref="BCrypt"/>, and must not be
    /// <see cref="HashType.None"/> for the extended schemes.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when any value is out of range.</exception>
    public BCryptOptions(int? workFactor = null, LongPasswordHandling longPasswordHandling = LongPasswordHandling.Throw, HashType? preHash = null)
    {
        if (workFactor is < BCryptCore.MinRounds or > BCryptCore.MaxRounds)
        {
            throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor,
                $"The work factor must be between {BCryptCore.MinRounds} and {BCryptCore.MaxRounds} (inclusive), or null for the default");
        }

        BCryptCore.ValidateLongPasswordHandling(longPasswordHandling);

        if (preHash.HasValue && preHash.Value is < HashType.None or > HashType.SHA512)
        {
            throw new ArgumentOutOfRangeException(nameof(preHash), preHash, null);
        }

        _workFactor = workFactor ?? 0;
        LongPasswordHandling = longPasswordHandling;
        PreHash = preHash;
    }

    /// <summary>
    /// Library default options.
    /// </summary>
    public static BCryptOptions Default => default;

    /// <summary>
    /// The log2 of the number of rounds of hashing to apply.
    /// </summary>
    public int WorkFactor => _workFactor == 0 ? BCryptCore.DefaultRounds : _workFactor;

    // The work factor as passed to the constructor, so the With* methods keep "unset" unset
    private int? ExplicitWorkFactor => _workFactor == 0 ? null : _workFactor;

    /// <summary>
    /// Policy for passwords exceeding bcrypt's 72-byte limit.
    /// </summary>
    public LongPasswordHandling LongPasswordHandling { get; }

    /// <summary>
    /// Pre-hash algorithm for the extended schemes; <c>null</c> uses the class default.
    /// </summary>
    public HashType? PreHash { get; }

    /// <summary>
    /// Returns a copy with the given work factor.
    /// </summary>
    /// <param name="workFactor">The log2 of the number of rounds of hashing to apply (4-31), or <c>null</c> for the default.</param>
    public BCryptOptions WithWorkFactor(int? workFactor) => new(workFactor, LongPasswordHandling, PreHash);

    /// <summary>
    /// Returns a copy with the given long-password policy.
    /// </summary>
    /// <param name="longPasswordHandling">Policy for passwords exceeding bcrypt's 72-byte limit.</param>
    public BCryptOptions WithLongPasswordHandling(LongPasswordHandling longPasswordHandling) => new(ExplicitWorkFactor, longPasswordHandling, PreHash);

    /// <summary>
    /// Returns a copy with the given pre-hash algorithm.
    /// </summary>
    /// <param name="preHash">Pre-hash algorithm; <c>null</c> uses the class default.</param>
    public BCryptOptions WithPreHash(HashType? preHash) => new(ExplicitWorkFactor, LongPasswordHandling, preHash);

    internal HashType ResolvePreHash(HashType classDefault) => PreHash ?? classDefault;

    /// <inheritdoc />
    public bool Equals(BCryptOptions other) =>
        WorkFactor == other.WorkFactor && LongPasswordHandling == other.LongPasswordHandling && PreHash == other.PreHash;

    /// <inheritdoc />
    public override bool Equals(object obj) => obj is BCryptOptions other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = WorkFactor;
            hash = (hash * 397) ^ (int)LongPasswordHandling;
            return (hash * 397) ^ (PreHash.HasValue ? (int)PreHash.Value + 2 : 0);
        }
    }

    /// <summary>Equality operator.</summary>
    public static bool operator ==(BCryptOptions left, BCryptOptions right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(BCryptOptions left, BCryptOptions right) => !left.Equals(right);
}
