namespace HaveIBeenPwned.PwnedPasswords.Abstractions;

public interface IFileStorage
{
    /// <summary>
    /// Get a stream to the file using the hash prefix
    /// </summary>
    /// <param name="hashPrefix">The hash prefix to use to lookup the file.</param>
    /// <param name="mode">The mode to get, either "sha1" or "ntlm"</param>
    /// <returns>Returns a <see cref="PwnedPasswordsFile"/> with a stream to access the k-anonymity SHA-1 file, containing the last modified date and the file ETag.</returns>
    /// <exception cref="System.IO.FileNotFoundException" />
    Task<PwnedPasswordsFile> GetHashFileAsync(string hashPrefix, string mode, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a hash file using the hash prefix.
    /// </summary>
    /// <param name="hashPrefix">The hash prefix to use to look up the file.</param>
    /// <param name="hashes">A sorted dictionary containing the hash prefixes as key and prevalence counts as value.</param>
    /// <param name="etag">The ETag of the existing file that can be checked to prevent update conflicts.</param>
    /// <param name="cancellationToken">A cancellation token to abort the update if signaled.</param>
    /// <returns>True of the file was successfully updated, otherwise false.</returns>
    Task<bool> UpdateHashFileAsync(string hashPrefix, SortedDictionary<string, int> hashes, string etag, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a validated ingestion file and associates it with a transaction to be processed when the transaction is confirmed.
    /// </summary>
    /// <param name="transactionId">The transaction id to associate with the ingestion file.</param>
    /// <param name="ingestionStream">A <see cref="Stream"/> containing the contents of the ingestion file.</param>
    /// <param name="cancellationToken">A cancellation token to abort if signaled.</param>
    /// <returns>An awaitable <see cref="Task"/></returns>
    Task StoreIngestionFileAsync(string transactionId, Stream ingestionStream, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an ingestion file for the specified transaction id.
    /// </summary>
    /// <param name="transactionId">The transaction id associated with the ingestion file.</param>
    /// <param name="cancellationToken">A cancellation token to abort if signaled.</param>
    /// <returns>A <see cref="Stream"/> containing the contents of the ingestion file.</returns>
    Task<Stream> GetIngestionFileAsync(string transactionId, CancellationToken cancellationToken = default);
}
