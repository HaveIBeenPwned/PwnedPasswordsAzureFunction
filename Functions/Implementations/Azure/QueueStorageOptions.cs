﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure;

public class QueueStorageOptions : IOptions<QueueStorageOptions>
{
    public string ConnectionString { get; set; } = "";
    public string Namespace { get; set; } = "";
    public QueueStorageOptions Value => this;
}
