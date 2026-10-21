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
/// Secret key ("pepper") for HMAC pre-hashing (<see cref="PreHashScheme.HmacSha3"/>).
/// </summary>
/// <remarks>
/// <para>
/// A distinct type so a key can't be passed where a password is expected (or vice versa); there is deliberately
/// no conversion from <see cref="string"/>. The key is encoded once on creation and zeroed on <see cref="Dispose"/>.
/// </para>
/// <para>
/// Instances are safe to share between threads (e.g. registered as a singleton), but must not be disposed
/// while a hash operation using them may still be running.
/// </para>
/// </remarks>
public sealed class HmacKey : IDisposable
{
    private readonly byte[] _key;
    private volatile bool _disposed;

    private HmacKey(byte[] key) => _key = key;

    /// <summary>
    /// Creates a key from text. The text is UTF-8 encoded, matching how earlier releases encoded string HMAC keys,
    /// so existing hashes still verify.
    /// </summary>
    /// <param name="key">The key text; must not be empty.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is empty or is not valid UTF-16.</exception>
    public static HmacKey FromString(ReadOnlySpan<char> key)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("HMAC key must not be empty", nameof(key));
        }

#if NETCOREAPP
        byte[] bytes = GC.AllocateArray<byte>(BCryptCore.SafeUTF8.GetByteCount(key), pinned: true);
        BCryptCore.SafeUTF8.GetBytes(key, bytes);
        return new HmacKey(bytes);
#else
        return new HmacKey(BCryptCore.EncodeUtf8(key, appendNul: false));
#endif
    }

    /// <summary>
    /// Creates a key from raw bytes (e.g. retrieved from a key vault). The input is copied.
    /// </summary>
    /// <param name="key">The key bytes; must not be empty.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is empty.</exception>
    public static HmacKey FromBytes(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("HMAC key must not be empty", nameof(key));
        }

#if NETCOREAPP
        // Pinned so the GC can't leave stray copies of the key behind when compacting
        byte[] bytes = GC.AllocateArray<byte>(key.Length, pinned: true);
#else
        byte[] bytes = new byte[key.Length];
#endif
        key.CopyTo(bytes);
        return new HmacKey(bytes);
    }

    internal ReadOnlySpan<byte> Span
    {
        get
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(_disposed, this);
#else
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HmacKey));
            }
#endif

            return _key;
        }
    }

    /// <summary>
    /// Zeroes the key. Any later use throws <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        BCryptCore.ZeroMemory(_key);
    }

    /// <summary>
    /// Returns a redacted placeholder so the key never ends up in logs.
    /// </summary>
    public override string ToString() => "HmacKey(***)";
}
