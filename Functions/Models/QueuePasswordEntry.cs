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
    [JsonPropertyName("sha1")]
    public SortedDictionary<string, List<HashEntry>> SHA1Entries { get; set; } = new SortedDictionary<string, List<HashEntry>>();
    [JsonPropertyName(name: "ntlm")]
    public SortedDictionary<string, List<HashEntry>> NTLMEntries { get; set; } = new SortedDictionary<string, List<HashEntry>>();
}
