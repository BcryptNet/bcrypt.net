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

using System.Runtime.CompilerServices;

namespace BCryptNet.IdentityExtensions;

/// <summary>
/// A validated scheme and its HMAC key, if any.
/// </summary>
internal readonly record struct ResolvedPreHash(PreHash PreHash, HmacKey HmacKey);

/// <summary>
/// Validated schemes for a <see cref="BCryptHasherOptions"/> instance, cached per instance, so options must not be
/// modified after first use.
/// </summary>
internal sealed class ResolvedPreHashes
{
    private static readonly ConditionalWeakTable<BCryptHasherOptions, ResolvedPreHashes> Cache = new();

    private ResolvedPreHashes(ResolvedPreHash current, ResolvedPreHash[] previous)
    {
        Current = current;
        Previous = previous;
    }

    internal ResolvedPreHash Current { get; }
    internal IReadOnlyList<ResolvedPreHash> Previous { get; }

    /// <exception cref="InvalidOperationException">Thrown when a scheme is misconfigured.</exception>
    /// <exception cref="PlatformNotSupportedException">Thrown when a scheme isn't supported on this platform.</exception>
    internal static ResolvedPreHashes For(BCryptHasherOptions options) => Cache.GetValue(options, Create);

    private static ResolvedPreHashes Create(BCryptHasherOptions options)
    {
        var current = Resolve(options.PreHash, nameof(BCryptHasherOptions.PreHash));
        var previous = options.PreviousPreHashes
            .Select((p, i) => Resolve(p, $"{nameof(BCryptHasherOptions.PreviousPreHashes)}[{i}]"))
            .ToArray();
        return new ResolvedPreHashes(current, previous);
    }

    private static ResolvedPreHash Resolve(PreHashOptions options, string name)
    {
        if (options is null)
        {
            throw new InvalidOperationException($"{nameof(BCryptHasherOptions)}.{name} must not be null");
        }

        PreHash preHash;
        try
        {
            preHash = options.ToPreHash();
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidOperationException)
        {
            throw new InvalidOperationException($"{nameof(BCryptHasherOptions)}.{name} is invalid: {ex.Message}", ex);
        }

        if (!preHash.IsSupported)
        {
            throw new PlatformNotSupportedException($"{nameof(BCryptHasherOptions)}.{name}: pre-hash {preHash} is not supported on this platform");
        }

        bool hasKey = !string.IsNullOrEmpty(options.HmacKey);
        if (preHash.RequiresKey != hasKey)
        {
            throw new InvalidOperationException(preHash.RequiresKey
                ? $"{nameof(BCryptHasherOptions)}.{name}: pre-hash {preHash} requires an {nameof(PreHashOptions.HmacKey)}"
                : $"{nameof(BCryptHasherOptions)}.{name}: pre-hash {preHash} does not use an {nameof(PreHashOptions.HmacKey)}; it would be ignored");
        }

        return new ResolvedPreHash(preHash, hasKey ? HmacKey.FromString(options.HmacKey) : null);
    }
}
