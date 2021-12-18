using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure
{
    /// <summary>
    /// Blob Storage instance to access hash prefix files
    /// </summary>
    public class BlobStorage : IFileStorage
    {
        private readonly BlobContainerClient _blobContainerClient;
        private readonly BlobContainerClient _ingestionContainerClient;
        private readonly ILogger _log;

        /// <summary>
        /// Create a new Blob storage access instance
        /// </summary>
        /// <param name="blobServiceClient">Client instance for accessing blob storage</param>
        /// <param name="options">Configuration instance</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        public BlobStorage(IOptions<BlobStorageOptions> options, ILogger<BlobStorage> log)
        {
            BlobStorageOptions storageOptions = options.Value;

            _log = log;
            var serviceClient = new BlobServiceClient(storageOptions.ConnectionString);
            _blobContainerClient = serviceClient.GetBlobContainerClient(storageOptions.BlobContainerName);
            _ingestionContainerClient = serviceClient.GetBlobContainerClient(storageOptions.BlobContainerName + "ingestion");
        }

        public async Task StoreIngestionFileAsync(string transactionId, Stream ingestionStream, CancellationToken cancellationToken = default)
        {
            await _ingestionContainerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            await _ingestionContainerClient.UploadBlobAsync(transactionId, ingestionStream, cancellationToken);
        }

        public async Task<Stream> GetIngestionFileAsync(string transactionId, CancellationToken cancellationToken = default)
        {
            await _ingestionContainerClient.CreateIfNotExistsAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            Response<BlobDownloadStreamingResult>? result = await _ingestionContainerClient.GetBlobClient(transactionId).DownloadStreamingAsync(cancellationToken: cancellationToken);
            return result.Value.Content;
        }

        public async Task<PwnedPasswordsFile> GetHashFileAsync(string hashPrefix, CancellationToken cancellationToken = default)
        {
            string fileName = $"{hashPrefix}.txt";
            BlobClient blobClient = _blobContainerClient.GetBlobClient(fileName);

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

        public async Task<bool> UpdateHashFileAsync(string hashPrefix, SortedDictionary<string, int> hashes, string etag, CancellationToken cancellationToken = default)
        {
            string fileName = $"{hashPrefix}.txt";
            BlobClient blobClient = _blobContainerClient.GetBlobClient(fileName);

            using (var memStream = new MemoryStream())
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
}
