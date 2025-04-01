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
using System.Collections.Generic;
using BCryptNet.BenchMarks._3._2._1;
using BCryptNet.BenchMarks._3._5.perfmerge_1;
using BCryptNet.BenchMarks._4._0._0;
using BenchmarkDotNet.Attributes;

namespace BCryptNet.BenchMarks;

#pragma warning disable 1591
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
[KeepBenchmarkFiles]
public class TestBcryptHashingEnhancedValidation
{
    public IEnumerable<object[]> Data()
    {
        yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD"];
    }

    private readonly string _baselineEnhancedHash = BCryptBaseLine.BCrypt.EnhancedHashPassword("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", BCryptBaseLine.HashType.SHA384, 12);
    private readonly string _bCrypt305PerfMerge1EnhancedHash = BCrypt305PerfMerge1.BCrypt.EnhancedHashPassword("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", BCrypt305PerfMerge1.HashType.SHA384, 12);
    private readonly string _bCryptV4PerfMerge1EnhancedHash = BCryptV4.BCrypt.EnhancedHashPassword("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", BCryptV4.HashType.SHA384, 12);
    private readonly string _bCryptExtendedV2EnhancedHash = BCryptExtendedV2.HashPassword("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 12, HashType.SHA384);
    private static readonly string Hmackey = Guid.NewGuid().ToString();
    private readonly string _bCryptExtendedV3EnhancedHash = BCryptExtendedV3.HashPassword(Hmackey, "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 12, HashType.SHA384);

    [Benchmark(Baseline = true)]
    [ArgumentsSource(nameof(Data))]
    public bool TestHashValidateEnhanced(string key)
    {
        return BCryptBaseLine.BCrypt.EnhancedVerify(key, _baselineEnhancedHash);
    }

    [Benchmark]
    [ArgumentsSource(nameof(Data))]
    public bool TestHashValidateEnhancedv305Perf1(string key)
    {
        return BCrypt305PerfMerge1.BCrypt.EnhancedVerify(key, _bCrypt305PerfMerge1EnhancedHash);
    }

    [Benchmark]
    [ArgumentsSource(nameof(Data))]
    public bool TestHashValidateEnhancedv4Perf(string key)
    {
        return BCryptV4.BCrypt.EnhancedVerify(key, _bCryptV4PerfMerge1EnhancedHash);
    }

    [Benchmark]
    [ArgumentsSource(nameof(Data))]
    public bool TestHashValidateEnhancedCurrent(string key)
    {
        return BCryptExtendedV2.Verify(key, _bCryptExtendedV2EnhancedHash);
    }

    [Benchmark]
    [ArgumentsSource(nameof(Data))]
    public bool TestHashValidateEnhancedNet8Plus(string key)
    {
        return BCryptExtendedV3.Verify(Hmackey, key, _bCryptExtendedV3EnhancedHash);
    }
}
