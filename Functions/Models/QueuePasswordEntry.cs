// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text.Json.Serialization;

namespace HaveIBeenPwned.PwnedPasswords.Models;

public class PasswordEntryBatch
{
    [JsonPropertyName("subId")]
    public string SubscriptionId { get; set; } = "";
    [JsonPropertyName("trxId")]
    public string TransactionId { get; set; } = "";
    [JsonPropertyName("items")]
    public Dictionary<string, List<PwnedPasswordsIngestionValue>> PasswordEntries { get; set; } = new Dictionary<string, List<PwnedPasswordsIngestionValue>>();
}
