﻿namespace Functions
{
    /// <summary>
    /// Wrapper class for holding the data for an append operation
    /// </summary>
    public class PwnedPasswordAppend
    {
        /// <summary>
        /// The SHA-1 hash passed in an append operation
        /// </summary>
        public string SHA1Hash { get; set; }

        /// <summary>
        /// The NTLM hash passed in an append operation
        /// </summary>
        public string NTLMHash { get; set; }

        /// <summary>
        /// The prevalence of this SHA-1/NTLM pair in the corpus
        /// </summary>
        public int Prevalence { get; set; }
    }
}