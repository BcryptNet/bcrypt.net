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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BCryptNet.IdentityExtensions;

/// <summary>
/// Options and their resolved schemes for one call.
/// </summary>
internal sealed record HasherSnapshot(BCryptHasherOptions Options, ResolvedPreHashes Schemes);

/// <summary>
/// The last valid <see cref="BCryptHasherOptions"/> from an <see cref="IOptionsMonitor{TOptions}"/>. Invalid reloads are
/// logged and ignored; if no valid options have been seen, the error is thrown.
/// </summary>
internal sealed class LiveHasherOptions
{
    private static readonly ConditionalWeakTable<IOptionsMonitor<BCryptHasherOptions>, LiveHasherOptions> States = new();

    private static readonly Action<ILogger, Exception> LogInvalidReload = LoggerMessage.Define(LogLevel.Error,
        new EventId(1, "InvalidReload"), "Reloaded BCryptHasherOptions are invalid; continuing with the previous valid options until fixed");

    private static readonly Action<ILogger, Exception> LogRecovered = LoggerMessage.Define(LogLevel.Information,
        new EventId(2, "ReloadRecovered"), "Reloaded BCryptHasherOptions are valid again and now in effect");

    private volatile HasherSnapshot _lastGood;
    private volatile bool _failing;

    internal static HasherSnapshot Current(IOptionsMonitor<BCryptHasherOptions> monitor, ILogger logger) =>
        States.GetValue(monitor, _ => new LiveHasherOptions()).Get(monitor, logger);

    private HasherSnapshot Get(IOptionsMonitor<BCryptHasherOptions> monitor, ILogger logger)
    {
        BCryptHasherOptions options;
        ResolvedPreHashes schemes;
        try
        {
            options = monitor.CurrentValue;
            schemes = ResolvedPreHashes.For(options);
        }
        catch (Exception ex) when (ex is OptionsValidationException or InvalidOperationException or PlatformNotSupportedException)
        {
            HasherSnapshot lastGood = _lastGood;
            if (lastGood is null)
            {
                throw;
            }

            if (!_failing)
            {
                _failing = true;
                if (logger is not null)
                {
                    LogInvalidReload(logger, ex);
                }
            }

            return lastGood;
        }

        HasherSnapshot snapshot = _lastGood;
        if (snapshot is null || !ReferenceEquals(snapshot.Options, options))
        {
            snapshot = new HasherSnapshot(options, schemes);
            _lastGood = snapshot;
        }

        if (_failing)
        {
            _failing = false;
            if (logger is not null)
            {
                LogRecovered(logger, null);
            }
        }

        return snapshot;
    }
}
