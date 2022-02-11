using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

using Microsoft.IO;

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure;

/// <summary>
/// Blob Storage instance to access hash prefix files
/// </summary>
public class BlobStorage : IFileStorage
{
    private static readonly RecyclableMemoryStreamManager s_manager = new(RecyclableMemoryStreamManager.DefaultBlockSize, RecyclableMemoryStreamManager.DefaultLargeBufferMultiple, RecyclableMemoryStreamManager.DefaultMaximumBufferSize);

    private readonly BlobContainerClient _blobContainerClient;
    private readonly BlobContainerClient _ingestionContainerClient;
    private readonly ILogger _log;

    /// <summary>
    /// Create a new Blob storage access instance
    /// </summary>
    /// <param name="blobServiceClient">Client instance for accessing blob storage</param>
    /// <param name="options">Configuration instance</param>
    /// <param name="log">Logger instance to emit diagnostic information to</param>
    public BlobStorage(IOptions<BlobStorageOptions> options, ILogger<BlobStorage> log, BlobServiceClient serviceClient)
    {
        BlobStorageOptions storageOptions = options.Value;

        _log = log;
        _blobContainerClient = serviceClient.GetBlobContainerClient(storageOptions.BlobContainerName);
        _ingestionContainerClient = serviceClient.GetBlobContainerClient(storageOptions.BlobContainerName + "ingestion");
        _ingestionContainerClient.CreateIfNotExists();
    }

    public async Task StoreIngestionFileAsync(string transactionId, Stream ingestionStream, CancellationToken cancellationToken = default)
    {
        await _ingestionContainerClient.UploadBlobAsync(transactionId, ingestionStream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Stream> GetIngestionFileAsync(string transactionId, CancellationToken cancellationToken = default)
    {
        Response<BlobDownloadStreamingResult>? result = await _ingestionContainerClient.GetBlobClient(transactionId).DownloadStreamingAsync(cancellationToken: cancellationToken);
        return result.Value.Content;
    }

    public async Task<PwnedPasswordsFile> GetHashFileAsync(string hashPrefix, CancellationToken cancellationToken = default)
    {
        string fileName = $"{hashPrefix}.txt";
        BlobClient blobClient = _blobContainerClient.GetBlobClient(fileName);

        try
        {
            MemoryStream recyclableStream = s_manager.GetStream();
            Response<BlobDownloadStreamingResult> response = await blobClient.DownloadStreamingAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            using (response.Value.Content)
            {
                await response.Value.Content.CopyToAsync(recyclableStream, cancellationToken).ConfigureAwait(false);
                recyclableStream.Seek(0, SeekOrigin.Begin);
                return new PwnedPasswordsFile(recyclableStream, response.Value.Details.LastModified, response.Value.Details.ETag.ToString());
            }
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _log.LogWarning("Hash file \"{FileName}\" not found.", fileName);
            throw new FileNotFoundException("Blob file not found", fileName, ex);
        }
    }

    public async Task<bool> UpdateHashFileAsync(string hashPrefix, SortedDictionary<string, int> hashes, string etag, CancellationToken cancellationToken = default)
    {
        string fileName = $"{hashPrefix}.txt";
        BlobClient blobClient = _blobContainerClient.GetBlobClient(fileName);

        using (MemoryStream memStream = s_manager.GetStream())
        {
            using (var writer = new StreamWriter(memStream))
            {
                foreach (KeyValuePair<string, int> item in hashes)
                {
                    writer.WriteLine($"{item.Key}:{item.Value:n0}");
                }

                writer.Flush();
                memStream.Seek(0, SeekOrigin.Begin);
                try
                {
                    await blobClient.UploadAsync(memStream, new BlobUploadOptions() { Conditions = new BlobRequestConditions() { IfMatch = new ETag(etag) } }, cancellationToken).ConfigureAwait(false);
                    return true;
                }
                catch (RequestFailedException ex) when (ex.Status == StatusCodes.Status412PreconditionFailed)
                {
                    // We have a write conflict, let's return false.
                    _log.LogWarning(ex, $"Unable to update blob {fileName} since ETag does not match.");
                    return false;
                }
            }
        }
    }
}
