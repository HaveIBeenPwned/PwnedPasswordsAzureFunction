// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

using Azure;
using Azure.Data.Tables;

namespace HaveIBeenPwned.PwnedPasswords.Models
{
    public class AppendTransactionEntity : ITableEntity
    {
        public string PartitionKey { get; set; } = "";
        public string RowKey { get; set; } = "";
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }
        public bool Confirmed { get; set; }
    }
}
