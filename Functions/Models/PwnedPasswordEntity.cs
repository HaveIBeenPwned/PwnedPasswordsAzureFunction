using Microsoft.WindowsAzure.Storage.Table;

namespace Functions
{
    /// <summary>
    /// Azure Table Storage entity for a Pwned Password
    /// </summary>
    public class PwnedPasswordEntity : TableEntity
    {
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
        public PwnedPasswordEntity () { }

        /// <summary>
        /// Creates a new PwnedPassword entity row from a <see cref="PwnedPasswordAppend"/>
        /// <param name="appendRequest">PwnedPassword append model data to use</param>
        /// </summary>
        public PwnedPasswordEntity(PwnedPasswordAppend appendRequest, int currentPrevalence = 0)
        {
            // Uses the pre-Blob Storage system of using the Partition key as the first five characters of
            // the hash and the row key as the remainder of the hash
            // See https://www.troyhunt.com/i-wanna-go-fast-why-searching-through-500m-pwned-passwords-is-so-quick/
            PartitionKey = appendRequest.SHA1Hash.Substring(0, 5);
            RowKey = appendRequest.SHA1Hash.Substring(5);
            NTLMHash = appendRequest.NTLMHash;
            Prevalence = appendRequest.Prevalence;
        }
    }
}
