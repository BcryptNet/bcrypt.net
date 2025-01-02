﻿// /*
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
using System.Text;

namespace BCryptNet.UnitTests;

public class Base64Tests
{
    [Fact]
    public void EncodeBase64_ValidInput_ReturnsCorrectBase64Encoding()
    {
        // Arrange
        byte[] byteArray = Encoding.UTF8.GetBytes("Hello, world!");
        int length = byteArray.Length;

        // Act
        char[] result = BCryptCore.EncodeBase64(byteArray, length);

        // Assert
        string expectedResult = "QETqZE6qGFbtakviGO";
        Assert.Equal(expectedResult, new string(result));
    }

    [Fact]
    public void EncodeBase64_InvalidLength_ThrowsArgumentException()
    {
        // Arrange
        byte[] byteArray = Encoding.UTF8.GetBytes("Hello, world!");
        int invalidLength = -1;

        // Act and Assert
        Assert.Throws<ArgumentException>(() => BCryptCore.EncodeBase64(byteArray, invalidLength));
    }
}
