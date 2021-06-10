using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Functions
{
    /// <summary>
    /// Blob Storage instance to access hash prefix files
    /// </summary>
    public class BlobStorage : IStorageService
    {
        private readonly BlobContainerClient _blobContainerClient;
        private readonly BlobStorageOptions storageOptions;
        private readonly ILogger _log;

        /// <summary>
        /// Create a new Blob storage access instance
        /// </summary>
        /// <param name="blobServiceClient">Client instance for accessing blob storage</param>
        /// <param name="options">Configuration instance</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        public BlobStorage(BlobServiceClient blobServiceClient, IOptions<BlobStorageOptions> options, ILogger<BlobStorage> log)
        {
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            storageOptions = options.Value;

            _log = log;
            _log.LogInformation("Querying container: {ContainerName}", storageOptions.BlobContainerName);
            _blobContainerClient = blobServiceClient.GetBlobContainerClient(storageOptions.BlobContainerName);
        }

        /// <summary>
        /// Get a stream to the file using the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <returns>Returns a <see cref="BlobStorageEntry"/> with a stream to access the k-anonymity SHA-1 file</returns>
        public async Task<BlobStorageEntry?> GetHashesByPrefix(string hashPrefix, CancellationToken cancellationToken = default)
        {
            var fileName = $"{hashPrefix}.txt";
            var blobClient = _blobContainerClient.GetBlobClient(fileName);

            try
            {
                var sw = Stopwatch.StartNew();

                sw.Start();
                var response = await blobClient.DownloadAsync(cancellationToken: cancellationToken);
                sw.Stop();

                _log.LogInformation("Hash file downloaded in {ElapsedMilliseconds}ms", sw.ElapsedMilliseconds.ToString("n0"));

                return new BlobStorageEntry(response.Value.Content, response.Value.Details.LastModified);
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _log.LogWarning("Hash file \"{FileName}\" not found.", fileName);
            }

            return null;
        }
    }
}
