using Newtonsoft.Json;

namespace Functions
{
    /// <summary>
    /// Wrapper class for holding the data for an append operation
    /// </summary>
    public class PwnedPasswordAppend
    {
        /// <summary>
        /// The SHA-1 hash passed in an append operation
        /// </summary>
        [JsonProperty("sha1Hash")]
        public string SHA1Hash { get; set; }

        /// <summary>
        /// The NTLM hash passed in an append operation
        /// </summary>
        [JsonProperty("ntlmHash")]
        public string NTLMHash { get; set; }

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
