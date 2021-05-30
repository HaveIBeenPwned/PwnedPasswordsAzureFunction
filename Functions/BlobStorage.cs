using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
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
    /// <returns>Returns a stream to access the k-anonymity SHA-1 file</returns>
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
                var totalSw = new Stopwatch();
                totalSw.Start();

                int identifiedLine = -1;
                List<string> lines = new List<string>();

                var searchSw = new Stopwatch();
                searchSw.Start();
                var blobReadStream = blockBlob.OpenRead();

                // Use a Stream reader to read line by line
                using (StreamReader reader = new StreamReader(blobReadStream))
                {
                    // We need to read every line to write it again - we can't append due to the use of Block Blobs
                    string readLine = reader.ReadLine();

                    int i = 0;
                    while (readLine != null)
                    {
                        // If our line starts with the hash
                        if (readLine.StartsWith(existingHash))
                        {
                            _log.Info("Found existing hash");
                            searchSw.Stop();
                            _log.Info($"Existing hash found in {searchSw.ElapsedMilliseconds:n0}ms");
                            identifiedLine = i;
                        }
                        lines.Add(readLine);
                        readLine = reader.ReadLine();
                        i++;
                    }

                    StringBuilder newLineBuilder = new StringBuilder();
                    newLineBuilder.Append(existingHash);
                    newLineBuilder.Append(":");

                    // This is an existing hash as we have an index for it
                    if (identifiedLine != -1)
                    {
                        string prevalenceCount = lines[identifiedLine].Substring(36);
                        if (!int.TryParse(prevalenceCount, out int existingPrevalence))
                        {
                            _log.Info("Unable to correctly parse value for " + existingHash);
                            return null;
                        }
                        int updatedPrevalence = existingPrevalence + prevalence;

                        // Construct updated entry line
                        newLineBuilder.Append(updatedPrevalence);

                        _log.Info($"Updated line in {fileName} will look like this: {newLineBuilder}");

                        lines[identifiedLine] = newLineBuilder.ToString();
                    }
                    // This is a new hash
                    else
                    {
                        _log.Info("Unable to find hash in existing corpus");

                        searchSw.Stop();
                        _log.Info($"Existing Blob Storage stream loaded and searched in {searchSw.ElapsedMilliseconds:n0}ms");

                        // Construct new entry line
                        newLineBuilder.Append(prevalence);

                        var insertSw = new Stopwatch();
                        insertSw.Start();
                        AddSorted(ref lines, newLineBuilder.ToString());
                        insertSw.Stop();

                        _log.Info($"Sorted insert took {insertSw.ElapsedMilliseconds:n0}ms");
                    }
                }

                var writeSw = new Stopwatch();
                writeSw.Start();
                var blobWriteStream = blockBlob.OpenWrite();
                // Write to the block - a CloudBlockBlob::OpenWrite call always overwrites
                using (StreamWriter writer = new StreamWriter(blobWriteStream))
                {
                    // Write every line
                    foreach (string line in lines)
                    {
                        writer.WriteLine(line);
                    }
                }
                writeSw.Stop();
                _log.Info($"Write back to Blob Storage took {searchSw.ElapsedMilliseconds:n0}ms");

                totalSw.Stop();
                _log.Info($"Total update of hash prevalence took {searchSw.ElapsedMilliseconds:n0}ms");

                // Return if the line identified does not exist
                return identifiedLine == -1;
            }
            catch (StorageException ex) when (ex.RequestInformation?.HttpStatusCode == 404)
            {
                _log.Warning($"Blob Storage couldn't find file \"{fileName}\"");
            }

            return null;
        }

        /// <summary>
        /// Add the item to the already sorted list
        /// </summary>
        /// <param name="list">Pointer to the list to use</param>
        /// <param name="line">Line to insert</param>
        private void AddSorted(ref List<string> list, string line)
        {
            if (list[list.Count - 1].CompareTo(line) <= 0)
            {
                list.Add(line);
                return;
            }
            if (list[0].CompareTo(line) >= 0)
            {
                list.Insert(0, line);
                return;
            }
            int index = list.BinarySearch(line);
            if (index < 0)
            {
                index = ~index;
            }
            list.Insert(index, line);
        }

        /// <summary>
        /// Get all all of the available hash prefix blobs for an Azure Table Storage update
        /// </summary>
        public async Task<List<Tuple<string, StreamWriter>>> GetHashPrefixBlobs()
        {
            List<Tuple<string, StreamWriter>> hashPrefixBlobs = new List<Tuple<string, StreamWriter>>();

            var blobList = _container.ListBlobs();
            foreach (var blobItem in blobList)
            {
                CloudBlockBlob blob = blobItem as CloudBlockBlob;
                var stream = await blob.OpenWriteAsync();
                var hashPrefix = blob.Name.Substring(0, 5);
                hashPrefixBlobs.Add(new Tuple<string, StreamWriter>(hashPrefix, new StreamWriter(stream)));
            }

            return hashPrefixBlobs;
        }
    }
}
