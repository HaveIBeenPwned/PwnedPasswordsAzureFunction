// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.IO;

using HaveIBeenPwned.PwnedPasswords.Implementations.Azure;

using Xunit;

namespace HaveIBeenPwned.PwnedPasswords.Tests;

public class BlobStorageTests
{
    [Fact]
    public void RendersHashesWithoutEndingNewline()
    {
        SortedDictionary<string, int> fakeHahes = new()
        {
            { "ABCDEF", 0 },
            { "FEDCBA", 1234 }
        };

        StringWriter writer = new();
        BlobStorage.RenderHashes(fakeHahes, writer);
        Assert.Equal($"ABCDEF:0{writer.NewLine}FEDCBA:1234", writer.ToString());
    }

    [Theory]
    [InlineData("FDFD0D9BC12735B077ACF1FA63D6F42229D:1")]
    [InlineData("FE5CCB19BA61C4C0873D391E987982FBBD3:86,453")]
    public void ParsesCultureIntSuccessfully(string hashLine)
    {
        if (!string.IsNullOrEmpty(hashLine) && hashLine.Length >= 37 && hashLine[35] == ':' && int.TryParse(hashLine[36..].Replace(",", ""), out int currentPrevalence) && currentPrevalence > 0)
        {
            return;
        }

        Assert.Fail($"Failed to parse {hashLine} successfully");
    }
}
