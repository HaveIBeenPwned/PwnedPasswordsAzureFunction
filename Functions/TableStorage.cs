using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
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
        private readonly TableClient _table;
        private readonly TableClient _metadataTable;
        private readonly ILogger _log;

        private static readonly HashSet<string> _localCache = new();

        public TableStorage(IConfiguration configuration, ILogger<TableStorage> log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            var tableName = configuration["TableStorageName"];
            var metadataTableName = configuration["MetadataTableStorageName"];

            var tableServiceClient = new TableServiceClient(storageConnectionString);

            _table = tableServiceClient.GetTableClient(tableName);
            _metadataTable = tableServiceClient.GetTableClient(metadataTableName);
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
            var i = 0;
            var query = _metadataTable.Query<PwnedPasswordEntity>(filter: $"PartitionKey eq {hashPrefix}");

            foreach (PwnedPasswordEntity entity in query)
            {
                responseBuilder.Append(entity.RowKey);
                responseBuilder.Append(':');
                responseBuilder.Append(entity.Prevalence);
                responseBuilder.Append('\n');
                // Use the last modified timestamp
                if (entity.Timestamp > lastModified)
                {
                    lastModified = entity.Timestamp;
                }
                i++;
            }

            if (i == 0)
            {
                _log.LogWarning($"Table Storage couldn't find any matching partition keys for \"{hashPrefix}\"");
            }

            return responseBuilder.ToString();
        }

        /// <summary>
        /// Check if the contentID is a duplicate request
        /// </summary>
        /// <param name="contentID">Hash of the deserialised content and the client's IP address for idempotency</param>
        /// <returns>True if the request is not a duplicate</returns>
        public async Task<bool> IsNotDuplicateRequest(string contentID)
        {
            var totalSw = Stopwatch.StartNew();
            var searchSw = Stopwatch.StartNew();

            // First check that this request isn't in the local cache
            if (_localCache.Contains(contentID))
            {
                searchSw.Stop();
                totalSw.Stop();
                _log.LogInformation($"Duplicate update request detected by local cache in {searchSw.ElapsedMilliseconds:n0}ms");
                return false;
            }

            // Cache miss, check it isn't in the metadata table
            try
            {
                var result = await _metadataTable.GetEntityAsync<TableEntity>("DuplicateRequest", contentID);
                searchSw.Stop();
                totalSw.Stop();
                _log.LogInformation($"Duplicate update request detected by metadata table in {searchSw.ElapsedMilliseconds:n0}ms");
                return false;
            }
            catch (RequestFailedException)
            {
                var duplicateSw = Stopwatch.StartNew();
                _localCache.Add(contentID);

                await _metadataTable.AddEntityAsync(new TableEntity("DuplicateRequest", contentID));

                duplicateSw.Stop();
                _log.LogInformation($"DuplicateRequest took {duplicateSw.ElapsedMilliseconds:n0}ms");

                totalSw.Stop();
                _log.LogInformation($"Total duplication check completed in {totalSw.ElapsedMilliseconds:n0}ms");

                return true;
            }
        }

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="append">The append request to process</param>
        public async Task UpdateHash(PwnedPasswordAppend append)
        {
            try
            {
                var totalSw = Stopwatch.StartNew();
                var retrieveSw = Stopwatch.StartNew();

                try
                {
                    var entityResponse = await _table.GetEntityAsync<PwnedPasswordEntity>(append.PartitionKey, append.RowKey);
                    retrieveSw.Stop();
                    _log.LogInformation($"Retrieval of partition key and row key completed in {retrieveSw.ElapsedMilliseconds:n0}ms");

                    var pwnedPassword = entityResponse.Value;
                    pwnedPassword.Prevalence += append.Prevalence;
                    var updateSw = Stopwatch.StartNew();
                    await _table.UpdateEntityAsync(pwnedPassword, ETag.All);

                    updateSw.Stop();
                    _log.LogInformation($"Update took {updateSw.ElapsedMilliseconds:n0}ms");
                }
                // If the item doesn't exist
                catch (RequestFailedException)
                {
                    retrieveSw.Stop();
                    _log.LogInformation($"Retrieval of partition key and row key completed in {retrieveSw.ElapsedMilliseconds:n0}ms");

                    var insertSw = Stopwatch.StartNew();
                    await _table.AddEntityAsync(new PwnedPasswordEntity(append));
                    insertSw.Stop();
                    _log.LogInformation($"Insert took {insertSw.ElapsedMilliseconds:n0}ms");
                }
                

                
                var lastModifiedSw = Stopwatch.StartNew();

                await _metadataTable.UpsertEntityAsync<TableEntity>(new TableEntity("LastModified", append.PartitionKey));

                lastModifiedSw.Stop();
                _log.LogInformation($"LastModified took {lastModifiedSw.ElapsedMilliseconds:n0}ms");

                totalSw.Stop();
                _log.LogInformation($"Total update completed in {totalSw.ElapsedMilliseconds:n0}ms");
            }
            catch (Exception e)
            {
                _log.LogError("An error occured", e, "TableStorage");
                throw;
            }
        }

        /// <summary>
        /// Get the modified partitions since the given time limit
        /// </summary>
        /// <param name="timeLimit">The time for which all timestamps equal and after will be returned</param>
        /// <returns>List of partition keys which have been modified</returns>
        public async Task<string[]> GetModifiedPartitions(DateTimeOffset timeLimit)
        {
            var modifiedPartitions = new List<string>();
            var sw = Stopwatch.StartNew();

            // Using a fixed partition key should speed up the operation
            var query = _metadataTable.QueryAsync<TableEntity>(filter: "PartitionKey eq LastModified");

            await foreach (TableEntity entity in query)
            {
                modifiedPartitions.Add(entity.RowKey);
            }

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
            await _metadataTable.DeleteEntityAsync(partitionKey, rowKey);
        }

        /// <summary>
        /// Deletes all duplicate request items 
        /// </summary>
        public async Task RemoveOldDuplicateRequests()
        {
            var now = DateTimeOffset.UtcNow;
            var deleteCount = 0;

            var sw = Stopwatch.StartNew();

            var query = _metadataTable.QueryAsync<TableEntity>(filter: "PartitionKey eq DuplicateRequest");

            await foreach (TableEntity entity in query)
            {
                if (now.AddMinutes(-30) > entity.Timestamp)
                {
                    await DeleteItemFromMetadataTable("DuplicateRequest", entity.RowKey);
                    deleteCount++;
                }
            }

            sw.Stop();
            _log.LogInformation($"Cleaning up {deleteCount} modified partitions took {sw.ElapsedMilliseconds:n0}ms");
        }
    }
}
