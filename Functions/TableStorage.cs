using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;

namespace Functions
{
    /// <summary>
    /// Table Storage wrapper 
    /// </summary>
    public class TableStorage
    {
        private readonly CloudTable table;
        private readonly TraceWriter _log;

        public TableStorage(TraceWriter log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = ConfigurationManager.AppSettings["PwnedPasswordsConnectionString"];
            var tableName = ConfigurationManager.AppSettings["TableStorageName"];

            var storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            var tableClient = storageAccount.CreateCloudTableClient();
            _log.Info($"Querying table: {tableName}");
            table = tableClient.GetTableReference(tableName);
        }

        /// <summary>
        /// Get a stream to the file using the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <param name="lastModified">Pointer to the DateTimeOffset for the last time that the blob was modified</param>
        /// <returns>Returns a stream to access the k-anonymity SHA-1 file</returns>
        public string GetByHashesByPrefix(string hashPrefix, out DateTimeOffset? lastModified)
        {
            lastModified = DateTimeOffset.MinValue;
            Stream stream = new MemoryStream();
            StringBuilder responseBuilder = new StringBuilder();
            using (StreamWriter writer = new StreamWriter(stream))
            {

                string partitionFilter = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, hashPrefix);
                TableQuery<PwnedPasswordEntity> query = new TableQuery<PwnedPasswordEntity>().Where(partitionFilter);

                var sw = new Stopwatch();
                sw.Start();

                var response = table.ExecuteQuery(query);

                sw.Stop();
                _log.Info($"Table Storage queried in {sw.ElapsedMilliseconds:n0}ms");

                int i = 0;
                foreach (PwnedPasswordEntity entity in response)
                {
                    responseBuilder.Append(entity.RowKey);
                    responseBuilder.Append(":");
                    responseBuilder.Append(entity.Prevalence);
                    responseBuilder.Append("\n");
                    // Use the last modified timestamp
                    if (entity.Timestamp > lastModified)
                    {
                        lastModified = entity.Timestamp;
                    }
                    i++;
                }

                if (i == 0)
                {
                    _log.Warning($"Table Storage couldn't find any matching partition keys for \"{hashPrefix}\"");
                }
            }
            return responseBuilder.ToString();
        }

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="sha1Hash">The SHA-1 hash entry to update (in full)</param>
        /// <param name="prevalence">The amount to increment the prevalence by. Defaults to 1.</param>
        /// <returns>Returns true if a new entry was added, false if an existing entry was updated, and null if no entries were updated</returns>
        public bool? UpdateHash(PwnedPasswordAppend append)
        {
            // Ensure that the hash is upper case
            string sha1Hash = append.SHA1Hash.ToUpper();
            string partitionKey = sha1Hash.Substring(0, 5);
            string rowKey = sha1Hash.Substring(5);
            
            try
            {
                var totalSw = new Stopwatch();
                totalSw.Start();

                var searchSw = new Stopwatch();
                searchSw.Start();

                TableOperation retrieve = TableOperation.Retrieve<PwnedPasswordEntity>(partitionKey, rowKey);
                TableResult result = table.Execute(retrieve);

                searchSw.Stop();
                _log.Info($"Search completed in {searchSw.ElapsedMilliseconds:n0}ms");

                PwnedPasswordEntity pwnedPassword = result.Result as PwnedPasswordEntity;

                if (pwnedPassword != null)
                {
                    pwnedPassword.Prevalence += append.Prevalence;
                    TableOperation update = TableOperation.Replace(pwnedPassword);
                    result = table.Execute(update);
                }
                else
                {
                    TableOperation insert = TableOperation.Insert(new PwnedPasswordEntity(append));
                    result = table.Execute(insert);
                }

                return pwnedPassword == null;
            }
            catch (Exception e)
            {
                _log.Error("An error occured", e, "TableStorage");
                return null;
            }
        }
    }
}
