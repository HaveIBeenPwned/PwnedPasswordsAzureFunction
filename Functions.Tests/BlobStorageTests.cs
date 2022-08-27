﻿// Licensed to the .NET Foundation under one or more agreements.
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
        SortedDictionary<string, int> fakeHahes = new SortedDictionary<string, int>();
        fakeHahes.Add("ABCDEF", 0);
        fakeHahes.Add("FEDCBA", 1234);

        StringWriter writer = new StringWriter();
        BlobStorage.RenderHashes(fakeHahes, writer);
        Assert.Equal($"ABCDEF:0{writer.NewLine}FEDCBA:1234", writer.ToString());
    }
}
