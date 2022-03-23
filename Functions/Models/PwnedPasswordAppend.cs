using System.Text.Json.Serialization;

namespace HaveIBeenPwned.PwnedPasswords.Models;

/// <summary>
/// Wrapper class for holding the data for an append operation
/// </summary>
public sealed class PwnedPasswordAppend
{
    private string _sha1Hash = "";
    private string _ntlmHash = "";

    /// <summary>
    /// The SHA-1 hash passed in an append operation
    /// </summary>
    [JsonPropertyName("sha1Hash")]
    public string SHA1Hash
    {
        get => _sha1Hash;
        set
        {
            _sha1Hash = value.ToUpper();
            PartitionKey = _sha1Hash[..5];
            RowKey = _sha1Hash[5..];
        }
    }

    /// <summary>
    /// Gets the partition key for the proposed append operation. This is the hash prefix for the K-anonyminity model
    /// </summary>
    public string PartitionKey { get; set; } = "";

    /// <summary>
    /// Get the row key for the proposed append operation. This is the remainder of the SHA-1 hash when combined with the <see cref="PartitionKey"/>
    /// </summary>
    public string RowKey { get; private set; } = "";

    /// <summary>
    /// The NTLM hash passed in an append operation
    /// </summary>
    [JsonPropertyName("ntlmHash")]
    public string NTLMHash
    {
        get => _ntlmHash;
        set => _ntlmHash = value.ToUpper();
    }

    /// <summary>
    /// The prevalence of this SHA-1/NTLM pair in the corpus
    /// </summary>
    [JsonPropertyName("prevalence")]
    public int Prevalence { get; set; }

    public override string ToString() => $"{SHA1Hash}|{NTLMHash}|{Prevalence}";
}
