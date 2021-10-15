using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HaveIBeenPwned.PwnedPasswords
{
    /// <summary>
    /// Blob Storage instance to access hash prefix files
    /// </summary>
    public class BlobStorage : IStorageService
    {
        private readonly BlobContainerClient _blobContainerClient;
        private readonly ILogger _log;

        /// <summary>
        /// Create a new Blob storage access instance
        /// </summary>
        /// <param name="blobServiceClient">Client instance for accessing blob storage</param>
        /// <param name="options">Configuration instance</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        public BlobStorage(BlobServiceClient blobServiceClient, IOptions<BlobStorageOptions> options, ILogger<BlobStorage> log)
        {
            BlobStorageOptions? storageOptions = options.Value;

            _log = log;
            _blobContainerClient = blobServiceClient.GetBlobContainerClient(storageOptions.BlobContainerName);
        }

        /// <summary>
        /// Get a stream to the file using the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <returns>Returns a <see cref="BlobStorageEntry"/> with a stream to access the k-anonymity SHA-1 file</returns>
        public async Task<BlobStorageEntry?> GetHashesByPrefix(string hashPrefix, CancellationToken cancellationToken = default)
        {
            string fileName = $"{hashPrefix}.txt";
            BlobClient? blobClient = _blobContainerClient.GetBlobClient(fileName);

            try
            {
                Response<Azure.Storage.Blobs.Models.BlobDownloadStreamingResult>? response = await blobClient.DownloadStreamingAsync(cancellationToken: cancellationToken);
                return new BlobStorageEntry(response.Value.Content, response.Value.Details.LastModified, response.Value.Details.ETag);
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _log.LogWarning("Hash file \"{FileName}\" not found.", fileName);
            }

            return null;
        }

        /// <summary>
        /// Updates the blob file with the hash prefix wih the provided file contents
        /// </summary>
        /// <param name="hashPrefix">Hash prefix file to update</param>
        /// <param name="hashPrefixFileContents">Contents to write to the file</param>
        public async Task UpdateBlobFile(string hashPrefix, string hashPrefixFileContents)
        {
            string? fileName = $"{hashPrefix}.txt";

            BlobClient? blobClient = _blobContainerClient.GetBlobClient(fileName);

            using (var memStream = new MemoryStream())
            {
                using (var writer = new StreamWriter(memStream))
                {
                    await writer.WriteAsync(hashPrefixFileContents);
                    await writer.FlushAsync();
                    memStream.Seek(0, SeekOrigin.Begin);
                    await blobClient.UploadAsync(memStream, overwrite: true);
                }
            }
        }

        /// <summary>
        /// Updates the blob file with the hash prefix wih the provided file contents
        /// </summary>
        /// <param name="hashPrefix">Hash prefix file to update</param>
        /// <param name="hashPrefixFileContents">Contents to write to the file</param>
        public async Task<bool> UpdateBlobFile(string hashPrefix, SortedDictionary<string, int> hashes, ETag etag)
        {
            string? fileName = $"{hashPrefix}.txt";
            BlobClient? blobClient = _blobContainerClient.GetBlobClient(fileName);

            using (var memStream = new MemoryStream())
            {
                using (var writer = new StreamWriter(memStream))
                {
                    foreach (var item in hashes)
                    {
                        writer.WriteLine($"{item.Key}:{item.Value:n0}");
                    }

                    writer.Flush();
                    memStream.Seek(0, SeekOrigin.Begin);
                    try
                    {
                        await blobClient.UploadAsync(memStream, new BlobUploadOptions() { Conditions = new BlobRequestConditions() { IfMatch = etag } });
                    }
                    catch(RequestFailedException ex) when (ex.Status == StatusCodes.Status412PreconditionFailed)
                    {
                        // We have a write conflict, let's return false.
                        _log.LogWarning(ex, $"Unable to update blob {fileName} since ETag does not match.");
                        return false;
                    }

                    return true;
                }
            }
        }
    }
}
