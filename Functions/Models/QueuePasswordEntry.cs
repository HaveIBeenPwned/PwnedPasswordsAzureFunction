// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;
using System.Text.Json.Serialization;

namespace HaveIBeenPwned.PwnedPasswords.Models;

public class PasswordEntryBatch
{
    [JsonPropertyName("subId")]
    public string SubscriptionId { get; set; } = "";
    [JsonPropertyName("trxId")]
    public string TransactionId { get; set; } = "";
    [JsonPropertyName("prefix")]
    public string Prefix { get; set; } = "";
    [JsonPropertyName("items")]
    public List<PasswordEntry> PasswordEntries { get; set; } = new List<PasswordEntry>();

    public class PasswordEntry
    {
        [JsonPropertyName("sha1")]
        public string SHA1Hash { get; set; } = "";
        [JsonPropertyName("ntlm")]
        public string NTLMHash { get; set; } = "";
        [JsonPropertyName("num")]
        public int Prevalence { get; set; }
    }
}
