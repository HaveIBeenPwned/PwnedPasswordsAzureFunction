using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

using Microsoft.IO;

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure;

/// <summary>
/// Blob Storage instance to access hash prefix files
/// </summary>
public class BlobStorage : IFileStorage
{
    private static readonly RecyclableMemoryStreamManager s_manager = new();

    private readonly BlobContainerClient _blobContainerSha1Client;
    private readonly BlobContainerClient _blobContainerNtlmClient;
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
        _blobContainerSha1Client = serviceClient.GetBlobContainerClient(storageOptions.BlobContainerName);
        _blobContainerNtlmClient = serviceClient.GetBlobContainerClient($"ntlm{storageOptions.BlobContainerName}");
        _ingestionContainerClient = serviceClient.GetBlobContainerClient(storageOptions.BlobContainerName + "ingestion");
        _ingestionContainerClient.CreateIfNotExists();
    }

    public async Task StoreIngestionFileAsync(string transactionId, Stream ingestionStream, CancellationToken cancellationToken = default)
    {
        await _ingestionContainerClient.UploadBlobAsync(transactionId, ingestionStream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Stream> GetIngestionFileAsync(string transactionId, CancellationToken cancellationToken = default)
    {
        Response<BlobDownloadStreamingResult> result = await _ingestionContainerClient.GetBlobClient(transactionId).DownloadStreamingAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.Value.Content;
    }

    public async Task<PwnedPasswordsFile> GetHashFileAsync(string hashPrefix, HashType mode, CancellationToken cancellationToken = default)
    {
        string fileName = $"{hashPrefix}.txt";
        BlobClient blobClient = GetHashBlobClient(mode, fileName);

        try
        {
            Response<BlobDownloadResult> response = await blobClient.DownloadContentAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            return new PwnedPasswordsFile(response.Value.Content.ToStream(), response.Value.Details.LastModified, response.Value.Details.ETag.ToString());
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _log.LogWarning("Hash file \"{FileName}\" not found.", fileName);
            throw new FileNotFoundException("Blob file not found", fileName, ex);
        }
    }

    public async Task<bool> UpdateHashFileAsync(string hashPrefix, HashType mode, SortedDictionary<string, int> hashes, string etag, CancellationToken cancellationToken = default)
    {
        string fileName = $"{hashPrefix}.txt";
        BlobClient blobClient = GetHashBlobClient(mode, fileName);

        using (RecyclableMemoryStream memStream = s_manager.GetStream())
        {
            using (var writer = new StreamWriter(memStream))
            {
                RenderHashes(hashes, writer);
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
                    _log.LogWarning(ex, "Unable to update blob {FileName} since ETag does not match.", fileName);
                    return false;
                }
            }
        }
    }

    private BlobClient GetHashBlobClient(HashType mode, string fileName) => mode == HashType.SHA1 ? _blobContainerSha1Client.GetBlobClient(fileName) : _blobContainerNtlmClient.GetBlobClient(fileName);

    public static void RenderHashes(SortedDictionary<string, int> hashes, TextWriter writer)
    {
        int i = 0;
        foreach (KeyValuePair<string, int> item in hashes)
        {
            if (++i < hashes.Count)
            {
                writer.WriteLine($"{item.Key}:{item.Value:D}");
            }
            else
            {
                writer.Write($"{item.Key}:{item.Value:D}");
            }
        }
    }
}
