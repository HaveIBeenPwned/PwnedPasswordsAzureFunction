using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Functions
{
    /// <summary>
    /// Table Storage wrapper 
    /// </summary>
    public sealed class TableStorage
    {
        private readonly CloudTable _table;
        private readonly CloudTable _modifiedTable;
        private readonly TraceWriter _log;

        public TableStorage(TraceWriter log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = ConfigurationManager.AppSettings["PwnedPasswordsConnectionString"];
            var tableName = ConfigurationManager.AppSettings["TableStorageName"];
            var modifiedTableName = ConfigurationManager.AppSettings["ModifiedTableStorageName"];

            var storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            var tableClient = storageAccount.CreateCloudTableClient();
            _log.Info($"Querying table: {tableName}");
            _table = tableClient.GetTableReference(tableName);
            _modifiedTable = tableClient.GetTableReference(modifiedTableName);
        }

        /// <summary>
        /// Get a string to write to the file containing all of the given hashes from the supplied prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <param name="lastModified">Pointer to the DateTimeOffset for the last time that the blob was modified</param>
        /// <returns>Returns a correctly formatted string to write to the Blob file</returns>
        public string GetByHashesByPrefix(string hashPrefix, out DateTimeOffset? lastModified)
        {
            lastModified = DateTimeOffset.MinValue;
            var responseBuilder = new StringBuilder();

            var partitionFilter = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, hashPrefix);
            var query = new TableQuery<PwnedPasswordEntity>().Where(partitionFilter);

            TableContinuationToken continuationToken = null;
            var i = 0;

            var sw = Stopwatch.StartNew();

            do
            {
                var response = _table.ExecuteQuerySegmented(query, continuationToken);

                foreach (var entity in response)
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
            }
            while (continuationToken != null);

            sw.Stop();
            _log.Info($"Table Storage queried in {sw.ElapsedMilliseconds:n0}ms");

            if (i == 0)
            {
                _log.Warning($"Table Storage couldn't find any matching partition keys for \"{hashPrefix}\"");
            }

            return responseBuilder.ToString();
        }

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="sha1Hash">The SHA-1 hash entry to update (in full)</param>
        /// <param name="prevalence">The amount to increment the prevalence by. Defaults to 1.</param>
        /// <returns>Returns true if a new entry was added, false if an existing entry was updated, and null if no entries were updated</returns>
        public async Task<bool?> UpdateHash(PwnedPasswordAppend append)
        {
            // Ensure that the hash is upper case
            append.SHA1Hash = append.SHA1Hash.ToUpper();
            var partitionKey = append.SHA1Hash.Substring(0, 5);
            var rowKey = append.SHA1Hash.Substring(5);
            
            try
            {
                var totalSw = Stopwatch.StartNew();
                var searchSw = Stopwatch.StartNew();

                var retrieve = TableOperation.Retrieve<PwnedPasswordEntity>(partitionKey, rowKey);
                var result = await _table.ExecuteAsync(retrieve);

                searchSw.Stop();
                _log.Info($"Search completed in {searchSw.ElapsedMilliseconds:n0}ms");

                var pwnedPassword = result.Result as PwnedPasswordEntity;

                if (pwnedPassword != null)
                {
                    pwnedPassword.Prevalence += append.Prevalence;
                    var update = TableOperation.Replace(pwnedPassword);
                    result = await _table.ExecuteAsync(update);
                }
                else
                {
                    var insert = TableOperation.Insert(new PwnedPasswordEntity(append));
                    result = await _table.ExecuteAsync(insert);
                }

                // Check if the key exists to save on transaction costs
                var retrieveModified = TableOperation.Retrieve<PwnedPasswordEntity>("LastModified", partitionKey);
                var modifiedResult = await _modifiedTable.ExecuteAsync(retrieveModified);
                if (modifiedResult.Result == null)
                {
                    var updateModified = TableOperation.InsertOrReplace(new TableEntity("LastModified", partitionKey));
                    result = await _modifiedTable.ExecuteAsync(updateModified);
                    _log.Info($"Adding new modified hash prefix {partitionKey} to modified table");
                }

                return pwnedPassword == null;
            }
            catch (Exception e)
            {
                _log.Error("An error occured", e, "TableStorage");
                return null;
            }
        }

        /// <summary>
        /// Get the modified partitions since the given time limit
        /// </summary>
        /// <param name="timeLimit">The time for which all timestamps equal and after will be returned</param>
        /// <returns>List of partition keys which have been modified</returns>
        public async Task<List<string>> GetModifiedPartitions(DateTimeOffset timeLimit)
        {
            List<string> modifiedPartitions = new List<string>();

            // Using a fixed partition key should speed up the operation
            var filterCondition = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, "LastModified");
            var query = new TableQuery<TableEntity>().Where(filterCondition);

            var sw = Stopwatch.StartNew();

            TableContinuationToken continuationToken = null;

            do
            {
                var response = await _modifiedTable.ExecuteQuerySegmentedAsync(query, continuationToken);

                foreach (var item in response)
                {
                    modifiedPartitions.Add(item.RowKey);
                }
            }
            while (continuationToken != null);

            sw.Stop();
            _log.Info($"Identifying {modifiedPartitions.Count} modified partitions since {timeLimit.UtcDateTime} took {sw.ElapsedMilliseconds:n0}ms");

            return modifiedPartitions;
        }

        /// <summary>
        /// Remove the given modified partition from the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to remove from the Storage Table</param>
        public async Task RemoveModifiedPartitionFromTable(string hashPrefix)
        {
            var entity = new TableEntity("LastModified", hashPrefix)
            {
                ETag = "*"
            };
            var delete = TableOperation.Delete(entity);
            await _modifiedTable.ExecuteAsync(delete);
        }
    }
}
