using Azure.Storage.Blobs;
using Functions.Dtos;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Functions.Services.Storage
{
    public class BlobStorageService : IStorageService
    {
        private readonly BlobServiceClient _blobServiceClient;
        private readonly StorageOptions _options;
        private readonly ILogger<BlobStorageService> _log;

        public BlobStorageService(BlobServiceClient blobServiceClient, IOptions<StorageOptions> options, ILogger<BlobStorageService> log)
        {
            _blobServiceClient = blobServiceClient;
            _options = options.Value;
            _log = log;
        }

        public async Task<HashFile> GetHashesByPrefix(string hashPrefix, CancellationToken cancellationToken = default)
        {
            var fileName = $"{hashPrefix}.txt";

            var container = _blobServiceClient.GetBlobContainerClient(_options.BlobContainerName);
            await container.CreateIfNotExistsAsync(cancellationToken: cancellationToken);

            var blobClient = container.GetBlobClient(fileName);

            if (await blobClient.ExistsAsync(cancellationToken))
            {
                try
                {
                    using var blobContent = new MemoryStream();

                    var blobProperties = await blobClient.GetPropertiesAsync(cancellationToken: cancellationToken);

                    var sw = Stopwatch.StartNew();
                    await blobClient.DownloadToAsync(blobContent, cancellationToken);
                    sw.Stop();

                    _log.LogInformation("Blob Storage stream queried in {ms}ms", sw.ElapsedMilliseconds.ToString("n0"));

                    return new HashFile
                    {
                        Content = blobContent.ToArray(),
                        LastModified = blobProperties.Value.LastModified
                    };
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Something went wrong when downloading file \"{fileName}\"", fileName);
                    throw;
                }
            }
            else
            {
                _log.LogWarning("Blob Storage couldn't find file \"{fileName}\"", fileName);

                return new NullHashFile();
            }
        }
    }
}
