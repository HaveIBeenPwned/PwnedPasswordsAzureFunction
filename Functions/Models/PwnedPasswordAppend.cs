﻿using Newtonsoft.Json;

namespace Functions
{
    /// <summary>
    /// Wrapper class for holding the data for an append operation
    /// </summary>
    public sealed class PwnedPasswordAppend
    {
        private string? _sha1Hash;

        private string? _partitionKey;
        private string? _rowKey;

        /// <summary>
        /// The SHA-1 hash passed in an append operation
        /// </summary>
        [JsonProperty("sha1Hash")]
        public string SHA1Hash
        {
            get => _sha1Hash;
            set
            {
                _sha1Hash = value.ToUpper();
                _partitionKey = _sha1Hash.Substring(0, 5);
                _rowKey = _sha1Hash.Substring(5);
            }
        }

        /// <summary>
        /// Gets the partition key for the proposed append operation
        /// </summary>
        public string PartitionKey => _partitionKey;

        /// <summary>
        /// Get the row key for the proposed append operation
        /// </summary>
        public string RowKey => _rowKey;

        private string? _ntlmHash;

        /// <summary>
        /// The NTLM hash passed in an append operation
        /// </summary>
        [JsonProperty("ntlmHash")]
        public string NTLMHash
        {
            get => _ntlmHash;
            set
            {
                _ntlmHash = value.ToUpper();
            }
        }

        /// <summary>
        /// The prevalence of this SHA-1/NTLM pair in the corpus
        /// </summary>
        [JsonProperty("prevalence")]
        public int Prevalence { get; set; }

        public override string ToString()
        {
            return $"{SHA1Hash}|{NTLMHash}|{Prevalence}";
        }
    }
}
