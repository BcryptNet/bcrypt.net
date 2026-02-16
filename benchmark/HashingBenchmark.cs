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
using BCryptNet.BenchMarks._4._0._3;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

#pragma warning disable 1591

namespace BCryptNet.BenchMarks
{
    [MemoryDiagnoser]
    [RPlotExporter]
    [RankColumn]
    [GcServer(true)]
    [Orderer(SummaryOrderPolicy.Declared)]
    [KeepBenchmarkFiles]
    [MarkdownExporterAttribute.GitHub]
    [ReturnValueValidator(failOnError: true)]
    public class HashingBenchmark
    {
        public static IEnumerable<object[]> Data()
        {
            yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"];
            yield return ["~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"];
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidate(string key, string salt, string hash)
        {
            return BCryptBaseLine.BCrypt.HashPassword(key, salt, enhancedEntropy: false);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidatePerf1(string key, string salt, string hash)
        {
            return BCrypt305PerfMerge1.BCrypt.HashPassword(key, salt, enhancedEntropy: false);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateV4(string key, string salt, string hash)
        {
            return BCryptV4.BCrypt.HashPassword(key, salt);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateV403(string key, string salt, string hash)
        {
            return BCryptV403.BCrypt.HashPassword(key, salt);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Data))]
        public string TestHashValidateCurrent(string key, string salt, string hash)
        {
            return BCrypt.HashPassword(key, salt);
        }
    }
}
