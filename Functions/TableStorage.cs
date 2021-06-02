using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
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
        private readonly CloudTable _metadataTable;
        private readonly ILogger _log;

        private static HashSet<string> _localCache = new HashSet<string>();

        public TableStorage(IConfiguration configuration, ILogger log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            var tableName = configuration["TableStorageName"];
            var metadataTableName = configuration["MetadataTableStorageName"];

            var storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            var tableClient = storageAccount.CreateCloudTableClient();
            _table = tableClient.GetTableReference(tableName);
            _metadataTable = tableClient.GetTableReference(metadataTableName);
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

            do
            {
                // TODO: Use await
                var response = _table.ExecuteQuerySegmentedAsync(query, continuationToken).Result;

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

            if (i == 0)
            {
                _log.LogWarning($"Table Storage couldn't find any matching partition keys for \"{hashPrefix}\"");
            }

            return responseBuilder.ToString();
        }

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="append">The append request to process</param>
        /// <param name="contentID">Hash of the deserialised content and the client's IP address for idempotency</param>
        /// <returns>Returns true if a new entry was added, false if an existing entry was updated, and null if no entries were updated</returns>
        public async Task<EUpdateHashResult> UpdateHash(PwnedPasswordAppend append, string contentID)
        {
            try
            {
                var totalSw = Stopwatch.StartNew();
                var searchSw = Stopwatch.StartNew();

                // First check that this request isn't in the local cache
                if (_localCache.Contains(contentID))
                {
                    _localCache.Add(contentID);
                    searchSw.Stop();
                    totalSw.Stop();
                    _log.LogInformation($"Duplicate update request detected by local cache in {searchSw.ElapsedMilliseconds:n0}ms");
                    return EUpdateHashResult.DuplicateRequest;
                }

                // Cache miss, check it isn't in the metadata table
                var retrieveDuplicateRequest = TableOperation.Retrieve<PwnedPasswordEntity>("DuplicateRequest", contentID);
                var duplicateRequestResult = await _metadataTable.ExecuteAsync(retrieveDuplicateRequest);

                if (duplicateRequestResult.Result != null)
                {
                    searchSw.Stop();
                    totalSw.Stop();
                    _log.LogInformation($"Duplicate update request detected by metadata table in {searchSw.ElapsedMilliseconds:n0}ms");
                    return EUpdateHashResult.DuplicateRequest;
                }

                var retrieve = TableOperation.Retrieve<PwnedPasswordEntity>(append.PartitionKey, append.RowKey);
                var result = await _table.ExecuteAsync(retrieve);

                searchSw.Stop();
                _log.LogInformation($"Search for duplicate completed in {searchSw.ElapsedMilliseconds:n0}ms");

                var pwnedPassword = result.Result as PwnedPasswordEntity;

                var insertOrUpdateSw = Stopwatch.StartNew();

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

                insertOrUpdateSw.Stop();
                _log.LogInformation($"Insert/Update took {insertOrUpdateSw.ElapsedMilliseconds:n0}ms");

                var lastModifiedSw = Stopwatch.StartNew();

                // Check if the key exists to save on transaction costs
                var retrieveModified = TableOperation.Retrieve<PwnedPasswordEntity>("LastModified", append.PartitionKey);
                var modifiedResult = await _metadataTable.ExecuteAsync(retrieveModified);
                if (modifiedResult.Result == null)
                {
                    var updateModified = TableOperation.InsertOrReplace(new TableEntity("LastModified", append.PartitionKey));
                    result = await _metadataTable.ExecuteAsync(updateModified);
                }

                lastModifiedSw.Stop();
                _log.LogInformation($"LastModified took {insertOrUpdateSw.ElapsedMilliseconds:n0}ms");

                var duplicateSw = Stopwatch.StartNew();
                var insertRequest = TableOperation.Insert(new TableEntity("DuplicateRequest", contentID));
                await _metadataTable.ExecuteAsync(insertRequest);
                duplicateSw.Stop();
                _log.LogInformation($"DuplicateRequest took {insertOrUpdateSw.ElapsedMilliseconds:n0}ms");

                totalSw.Stop();
                _log.LogInformation($"Total update completed in {totalSw.ElapsedMilliseconds:n0}ms");

                return (pwnedPassword == null) ? EUpdateHashResult.Added : EUpdateHashResult.Updated;
            }
            catch (Exception e)
            {
                _log.LogError("An error occured", e, "TableStorage");
                return EUpdateHashResult.Error;
            }
        }

        /// <summary>
        /// Get the modified partitions since the given time limit
        /// </summary>
        /// <param name="timeLimit">The time for which all timestamps equal and after will be returned</param>
        /// <returns>List of partition keys which have been modified</returns>
        public async Task<string[]> GetModifiedPartitions(DateTimeOffset timeLimit)
        {
            List<string> modifiedPartitions = new List<string>();

            // Using a fixed partition key should speed up the operation
            var filterCondition = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, "LastModified");
            var query = new TableQuery<TableEntity>().Where(filterCondition);

            var sw = Stopwatch.StartNew();

            TableContinuationToken continuationToken = null;

            do
            {
                var response = await _metadataTable.ExecuteQuerySegmentedAsync(query, continuationToken);

                foreach (var item in response)
                {
                    modifiedPartitions.Add(item.RowKey);
                }
            }
            while (continuationToken != null);

            sw.Stop();
            _log.LogInformation($"Identifying {modifiedPartitions.Count} modified partitions since {timeLimit.UtcDateTime} took {sw.ElapsedMilliseconds:n0}ms");

            return modifiedPartitions.ToArray();
        }

        /// <summary>
        /// Remove the given modified partition from the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to remove from the Storage Table</param>
        public async Task RemoveModifiedPartitionFromTable(string hashPrefix)
        {
            await DeleteItemFromMetadataTable("LastModified", hashPrefix);
        }


        private async Task DeleteItemFromMetadataTable(string partitionKey, string rowKey)
        {
            var entity = new TableEntity(partitionKey, rowKey)
            {
                ETag = "*"
            };
            var delete = TableOperation.Delete(entity);
            await _metadataTable.ExecuteAsync(delete);
        }

        /// <summary>
        /// Deletes all items 
        /// </summary>
        public async Task RemoveOldDuplicateRequests()
        {
            var now = DateTimeOffset.UtcNow;
            List<TableEntity> deleteList = new List<TableEntity>();

            var filterCondition = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, "DuplicateRequest");
            var query = new TableQuery<TableEntity>().Where(filterCondition);

            var sw = Stopwatch.StartNew();

            TableContinuationToken continuationToken = null;

            do
            {
                var response = await _metadataTable.ExecuteQuerySegmentedAsync(query, continuationToken);

                foreach (var item in response)
                {
                    deleteList.Add(item);
                }
            }
            while (continuationToken != null);

            var deleteCount = 0;
            for (int i = 0; i < deleteList.Count; i++)
            {
                if (now.AddMinutes(-30) > deleteList[i].Timestamp)
                {
                    await DeleteItemFromMetadataTable("DuplicateRequest", deleteList[i].RowKey);
                    deleteCount++;
                }
            }

            sw.Stop();
            _log.LogInformation($"Cleaning up {deleteCount} modified partitions took {sw.ElapsedMilliseconds:n0}ms");
        }
    }

    public enum EUpdateHashResult : int
    {
        Added = 0,
        Updated = 1,
        DuplicateRequest = 2,
        Error = 4,
    }
}
