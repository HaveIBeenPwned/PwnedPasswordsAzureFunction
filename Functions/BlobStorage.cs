using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
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

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="sha1Hash">The SHA-1 hash entry to update (in full)</param>
        /// <param name="prevalence">The amount to increment the prevalence by. Defaults to 1.</param>
        /// <returns>Returns true if a new entry was added, false if an existing entry was updated, and null if no entries were updated</returns>
        public bool? UpdateHash(string sha1Hash, int prevalence = 1)
        {
            // Ensure that the hash is upper case
            sha1Hash = sha1Hash.ToUpper();
            string hashPrefix = sha1Hash.Substring(0, 5);
            string existingHash = sha1Hash.Substring(5);
            var fileName = $"{hashPrefix}.txt";
            var blockBlob = _container.GetBlockBlobReference(fileName);

            try
            {
                bool hasFound = false;

                var sw = new Stopwatch();
                sw.Start();
                var blobStream = blockBlob.OpenRead();

                // Use a Stream reader to read line by line
                using (StreamReader reader = new StreamReader(blobStream))
                {
                    string readLine = reader.ReadLine();
                    while (readLine != null)
                    {
                        // If our line starts with the hash
                        if (readLine.StartsWith(existingHash))
                        {
                            _log.Info("Found existing hash");
                            sw.Stop();
                            _log.Info($"Existing hash found in {sw.ElapsedMilliseconds:n0}ms");
                            hasFound = true;
                            break;
                        }

                        readLine = reader.ReadLine();
                    }

                    StringBuilder newLine = new StringBuilder();
                    newLine.Append(existingHash);
                    newLine.Append(":");

                    // This is an existing hash
                    if (hasFound)
                    {
                        // Split at the : to get the number afterwards
                        string[] splitLine = readLine.Split(':');
                        if (splitLine.Length < 2 || !int.TryParse(splitLine[1], out int existingPrevalence))
                        {
                            _log.Info("Unable to correctly parse value for " + existingHash);
                            return null;
                        }
                        int updatedPrevalence = existingPrevalence + prevalence;

                        // Construct updated entry line
                        newLine.Append(updatedPrevalence);

                        _log.Info($"Updated line in {fileName} will look like this: {newLine}");
                    }
                    // This is a new hash
                    else
                    {
                        _log.Info("Unable to find hash in existing corpus");

                        sw.Stop();
                        _log.Info($"Existing Blob Storage stream loaded and searched in {sw.ElapsedMilliseconds:n0}ms");

                        // Construct new entry line
                        newLine.Append(prevalence);

                        _log.Info($"New line in {fileName} will look like this: {newLine}");
                    }

                    // TODO: Update existing entry in Azure Blob Storage
                }

                return !hasFound;
            }
            catch (StorageException ex) when (ex.RequestInformation?.HttpStatusCode == 404)
            {
                _log.Warning($"Blob Storage couldn't find file \"{fileName}\"");
            }

            return null;
        }
  }
}
