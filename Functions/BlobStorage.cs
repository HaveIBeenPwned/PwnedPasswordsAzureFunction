using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

namespace Functions
{
    /// <summary>
    /// Blob Storage instance to access hash prefix files
    /// </summary>
    public class BlobStorage : IStorageService
    {
        private readonly CloudBlobContainer _container;
        private readonly ILogger _log;

        /// <summary>
        /// Create a new Blob storage access instance
        /// </summary>
        /// <param name="configuration">Configuration instance</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        public BlobStorage(IConfiguration configuration, ILogger<BlobStorage> log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            var containerName = configuration["BlobContainerName"];

            var storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            var blobClient = storageAccount.CreateCloudBlobClient();
            _log.LogInformation("Querying container: {ContainerName}", containerName);
            _container = blobClient.GetContainerReference(containerName);
        }

        /// <summary>
        /// Get a stream to the file using the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <returns>Returns a <see cref="BlobStorageEntry"/> with a stream to access the k-anonymity SHA-1 file</returns>
        public async Task<BlobStorageEntry?> GetHashesByPrefix(string hashPrefix)
        {
            var fileName = $"{hashPrefix}.txt";
            var blockBlob = _container.GetBlockBlobReference(fileName);

            try
            {
                var sw = new Stopwatch();
                sw.Start();
                var blobStream = await blockBlob.OpenReadAsync();
                sw.Stop();
                _log.LogInformation("Blob Storage stream queried in {ElapsedMilliseconds}ms", sw.ElapsedMilliseconds.ToString("n0"));

                return new BlobStorageEntry(blobStream, blockBlob.Properties.LastModified);
            }
            catch (StorageException ex) when (ex.RequestInformation?.HttpStatusCode == 404)
            {
                _log.LogWarning("Blob Storage couldn't find file \"{FileName}\"", fileName);
            }

            return null;
        }
    }
}
