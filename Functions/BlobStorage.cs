using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Net;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

namespace Functions
{
    public class BlobStorage
    {
        private readonly CloudBlobContainer _container;
        private readonly TraceWriter _log;

        public BlobStorage(TraceWriter log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = ConfigurationManager.AppSettings["PwnedPasswordsConnectionString"];
            var containerName = ConfigurationManager.AppSettings["BlobContainerName"];

            var storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            var blobClient = storageAccount.CreateCloudBlobClient();
            _log.Info($"Querying container: {containerName}");
            _container = blobClient.GetContainerReference(containerName);
        }

        public Stream GetByHashesByPrefix(string hashPrefix, out DateTimeOffset? lastModified)
        {
            var fileName = $"{hashPrefix}.txt";
            var blockBlob = _container.GetBlockBlobReference(fileName);

            try
            {
                var sw = new Stopwatch();
                sw.Start();
                var blobStream = blockBlob.OpenRead();
                sw.Stop();
                _log.Info($"Blob Storage stream queried in {sw.ElapsedMilliseconds:n0}ms");

                lastModified = blockBlob.Properties.LastModified;

                return blobStream;
            }
            catch (StorageException ex)
            {
                if (!ex.Message.Contains("Not Found"))
                {
                    throw;
                }

                _log.Warning($"Blob Storage couldn't find file \"{fileName}\"");
            }

            lastModified = null;
            return null;
        }
    }
}
