using System;
using Azure;
using Azure.Data.Tables;

namespace Functions
{
    /// <summary>
    /// Azure Table Storage entity for a Pwned Password
    /// </summary>
    public class PwnedPasswordEntity : ITableEntity
    {
        /// <summary>
        /// The Partition Key for this entity
        /// </summary>
        public string PartitionKey { get; set; }

        /// <summary>
        /// The Row Key for this entity
        /// </summary>
        public string RowKey { get; set; }

        /// <summary>
        /// Last time this entity was updated
        /// </summary>
        public DateTimeOffset? Timestamp { get; set; }

        /// <summary>
        /// ETag for this entity
        /// </summary>
        public ETag ETag { get; set; }

        /// <summary>
        /// The NTLM hash to store in the table
        /// </summary>
        public string NTLMHash { get; set; }

        /// <summary>
        /// The current prevalence of occurances this SHA-1 password has been seen in a breach or exposed through other means
        /// </summary>
        public int Prevalence { get; set; }

        /// <summary>
        /// Empty constructor - required by TableEntity
        /// </summary>
        public PwnedPasswordEntity ()
        {
            PartitionKey = "";
            RowKey = "";
            NTLMHash = "";
        }

        /// <summary>
        /// Creates a new PwnedPassword entity row from a <see cref="PwnedPasswordAppend"/>
        /// <param name="appendRequest">PwnedPassword append model data to use</param>
        /// </summary>
        public PwnedPasswordEntity(PwnedPasswordAppend appendRequest)
        {
            // Uses the pre-Blob Storage system of using the Partition key as the first five characters of
            // the hash and the row key as the remainder of the hash
            // See https://www.troyhunt.com/i-wanna-go-fast-why-searching-through-500m-pwned-passwords-is-so-quick/
            PartitionKey = appendRequest.PartitionKey;
            RowKey = appendRequest.RowKey;
            NTLMHash = appendRequest.NTLMHash;
            Prevalence = appendRequest.Prevalence;
        }
    }
}
