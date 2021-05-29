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
  /// <summary>
  /// Blob Storage instance to access hash prefix files
  /// </summary>
  public class BlobStorage
  {
    private readonly CloudBlobContainer _container;
    private readonly TraceWriter _log;

    /// <summary>
    /// Create a new Blob storage access instance
    /// </summary>
    /// <param name="log">Trace writer to use to write to the log</param>
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

    /// <summary>
    /// Get a stream to the file using the hash prefix
    /// </summary>
    /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
    /// <param name="lastModified">Pointer to the DateTimeOffset for the last time that the blob was modified</param>
    /// <returns>Returns a stream to access the k-anonyminity SHA-1 file</returns>
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
      catch (StorageException ex) when (ex.RequestInformation?.HttpStatusCode == 404)
      {
        _log.Warning($"Blob Storage couldn't find file \"{fileName}\"");
      }

      lastModified = null;
      return null;
    }
  }
}
