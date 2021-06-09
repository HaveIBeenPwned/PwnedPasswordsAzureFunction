using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;

namespace Functions
{
    /// <summary>
    /// Blob Storage instance to access hash prefix files
    /// </summary>
    public sealed class BlobStorage
    {
        private readonly ILogger<BlobStorage> _log;
        private readonly BlobContainerClient _blobContainerClient;

        /// <summary>
        /// Create a new Blob storage access instance
        /// </summary>
        /// <param name="configuration">Configuration instance</param>
        /// <param name="log">Logger instance to emit diagnostic information</param>
        /// <param name="blobServiceClient">Client instance for accessing blob storage</param>
        public BlobStorage(IConfiguration configuration, ILogger<BlobStorage> log, BlobServiceClient blobServiceClient)
        {
            _log = log;

            var containerName = configuration["BlobContainerName"];

            _log.LogInformation("Querying container: {ContainerName}", containerName);
            _blobContainerClient = blobServiceClient.GetBlobContainerClient(containerName);
        }

        /// <summary>
        /// Get a stream to the file using the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <returns>Returns a <see cref="BlobStorageEntry"/> with a stream to access the k-anonymity SHA-1 file</returns>
        public async Task<BlobStorageEntry?> GetByHashesByPrefix(string hashPrefix)
        {
            var fileName = $"{hashPrefix}.txt";
            var blobClient = _blobContainerClient.GetBlobBaseClient(fileName);

            try
            {
                var sw = new Stopwatch();
                sw.Start();
                var response = await blobClient.DownloadStreamingAsync();
                sw.Stop();
                _log.LogInformation("Blob Storage stream queried in {ElapsedMilliseconds}ms", sw.ElapsedMilliseconds.ToString("n0"));

                return new BlobStorageEntry(response.Value.Content, response.Value.Details.LastModified);
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _log.LogWarning("Blob Storage couldn't find file \"{FileName}\"", fileName);
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
            var fileName = $"{hashPrefix}.txt";

            var blobClient = _blobContainerClient.GetBlobClient(fileName);

            using (MemoryStream memStream = new MemoryStream())
            {
                using (StreamWriter writer = new StreamWriter(memStream))
                {
                    await writer.WriteAsync(hashPrefixFileContents);
                    await writer.FlushAsync();
                    memStream.Seek(0, SeekOrigin.Begin);
                    await blobClient.UploadAsync(memStream, overwrite: true);
                }
            }
        }
    }
}
