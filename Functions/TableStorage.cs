using Azure;
using Azure.Data.Tables;

using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace HaveIBeenPwned.PwnedPasswords
{
    /// <summary>
    /// Table Storage wrapper 
    /// </summary>
    public sealed class TableStorage
    {
        private readonly TableClient _transactionTable;
        private readonly TableClient _dataTable;
        private readonly TableClient _hashDataTable;
        private readonly TableClient _cachePurgeTable;
        private readonly ILogger _log;
        private bool _initialized = false;

        private static readonly HashSet<string> _localCache = new HashSet<string>();

        public TableStorage(IConfiguration configuration, ILogger<TableStorage> log)
        {
            _log = log;
            string? storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            string? tableNamespace = configuration["TableNamespace"];
            var tableServiceClient = new TableServiceClient(storageConnectionString);
            _transactionTable = tableServiceClient.GetTableClient($"{tableNamespace}transactions");
            _dataTable = tableServiceClient.GetTableClient($"{tableNamespace}transactiondata");
            _hashDataTable = tableServiceClient.GetTableClient($"{tableNamespace}hashdata");
            _cachePurgeTable = tableServiceClient.GetTableClient($"{tableNamespace}cachepurge");
        }

        private async ValueTask InitializeIfNeededAsync()
        {
            if (!_initialized)
            {
                await _transactionTable.CreateIfNotExistsAsync();
                await _dataTable.CreateIfNotExistsAsync();
                await _hashDataTable.CreateIfNotExistsAsync();
                await _cachePurgeTable.CreateIfNotExistsAsync();
                _initialized = true;
            }
        }

        /// <summary>
        /// Get a string to write to the file containing all of the given hashes from the supplied prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the blob storage file</param>
        /// <param name="lastModified">Pointer to the DateTimeOffset for the last time that the blob was modified</param>
        /// <returns>Returns a correctly formatted string to write to the Blob file</returns>
        public async Task<(string response, DateTimeOffset? lastModified)> GetByHashesByPrefix(string hashPrefix)
        {
            /*
            DateTimeOffset? lastModified = DateTimeOffset.MinValue;
            var responseBuilder = new StringBuilder();
            var i = 0;
            var query = _table.QueryAsync<PwnedPasswordEntity>(x => x.PartitionKey == hashPrefix);

            await foreach (PwnedPasswordEntity entity in query)
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

            return (responseBuilder.ToString(), lastModified);
            */
            return default;
        }

        public async Task<string> InsertAppendData(PwnedPasswordAppend[] data, string clientId)
        {
            await InitializeIfNeededAsync();
            string transactionId = Guid.NewGuid().ToString();
            await _transactionTable.AddEntityAsync(new AppendTransactionEntity { PartitionKey = clientId, RowKey = transactionId, Confirmed = false });

            TableTransactionAction[] transactionActions = new TableTransactionAction[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                PwnedPasswordAppend? item = data[i];
                transactionActions[i] = new TableTransactionAction(TableTransactionActionType.Add, new AppendDataEntity { PartitionKey = transactionId, RowKey = item.SHA1Hash, NTLMHash = item.NTLMHash, Prevalence = item.Prevalence });
            }

            await _dataTable.SubmitTransactionAsync(transactionActions);
            return transactionId;
        }

        public async Task<IActionResult> ConfirmAppendDataAsync(string subscriptionId, string transactionId, StorageQueue storageQueue)
        {
            await InitializeIfNeededAsync();
            try
            {
                Response<AppendTransactionEntity> transactionEntityResponse = await _transactionTable.GetEntityAsync<AppendTransactionEntity>(subscriptionId, transactionId);
                if (!transactionEntityResponse.Value.Confirmed)
                {
                    AsyncPageable<AppendDataEntity>? transactionDataResponse = _dataTable.QueryAsync<AppendDataEntity>(x => x.PartitionKey == transactionId);
                    transactionEntityResponse.Value.Confirmed = true;
                    var updateResponse = await _transactionTable.UpdateEntityAsync(transactionEntityResponse.Value, transactionEntityResponse.Value.ETag);

                    await foreach (AppendDataEntity? item in transactionDataResponse)
                    {
                        // Send all the entities to the queue for processing.
                        await storageQueue.PushPassword(subscriptionId, item);
                    }

                    _log.LogInformation("Transaction {TransactionId} confirmed.", transactionId);
                    return new OkResult();
                }

                return new ContentResult { StatusCode = StatusCodes.Status400BadRequest, Content = "TransactionId has already been confirmed.", ContentType = "text/plain" };
            }
            catch (RequestFailedException e) when (e.Status == 404)
            {
                return new ContentResult { StatusCode = StatusCodes.Status404NotFound, Content = "TransactionId not found.", ContentType = "text/plain" };
            }
            catch(RequestFailedException e) when (e.Status == StatusCodes.Status409Conflict)
            {
                return new ContentResult { StatusCode = StatusCodes.Status409Conflict, Content = "TransactionId is already being confirmed.", ContentType = "text/plain" };
            }
            catch (RequestFailedException e)
            {
                _log.LogError(e, "Error looking up/updating transaction with id = {TransactionId} for subscription {SubscriptionId}.", transactionId, subscriptionId);
                return new ContentResult { StatusCode = StatusCodes.Status500InternalServerError, Content = "An error occurred.", ContentType = "text/plain" };
            }
        }

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="append">The append request to process</param>
        public async Task UpdateHashTable(AppendQueueItem append)
        {
            await InitializeIfNeededAsync();
            string partitionKey = append.SHA1Hash.Substring(0, 5);
            string rowKey = append.SHA1Hash.Substring(5);

            try
            {
                while (!await UpsertPwnedPasswordEntity(partitionKey, rowKey, append.NTLMHash, append.Prevalence))
                {

                }

                await _cachePurgeTable.UpsertEntityAsync(new TableEntity($"{DateTime.UtcNow.Year}-{DateTime.UtcNow.Month}", partitionKey));
            }
            catch (Exception e)
            {
                _log.LogError(e, "An error occured");
                throw;
            }
        }

        private async Task<bool> UpsertPwnedPasswordEntity(string partitionKey, string rowKey, string ntlmHash, int prevalence)
        {
            try
            {
                try
                {
                    var entityResponse = await _hashDataTable.GetEntityAsync<PwnedPasswordEntity>(partitionKey, rowKey);
                    var pwnedPassword = entityResponse.Value;
                    pwnedPassword.Prevalence += prevalence;
                    await _hashDataTable.UpdateEntityAsync(pwnedPassword, pwnedPassword.ETag);
                }
                // If the item doesn't exist
                catch (RequestFailedException e) when (e.Status == StatusCodes.Status404NotFound)
                {
                    var insertSw = Stopwatch.StartNew();
                    await _hashDataTable.AddEntityAsync(new PwnedPasswordEntity { PartitionKey = partitionKey, RowKey = rowKey, NTLMHash = ntlmHash, Prevalence = prevalence });
                }
            }
            catch(RequestFailedException e) when (e.Status == StatusCodes.Status412PreconditionFailed || e.Status == StatusCodes.Status409Conflict)
            {
                _log.LogWarning(e, $"Unable to update or insert PwnedPasswordEntity {partitionKey}:{rowKey} as it has already been updated.");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Get the modified partitions since the given time limit
        /// </summary>
        /// <param name="timeLimit">The time for which all timestamps equal and after will be returned</param>
        /// <returns>List of partition keys which have been modified</returns>
        public async Task<string[]> GetModifiedPartitions(DateTimeOffset timeLimit)
        {
            /*
            var modifiedPartitions = new List<string>();
            var sw = Stopwatch.StartNew();

            // Using a fixed partition key should speed up the operation
            var query = _metadataTable.QueryAsync<TableEntity>(x => x.PartitionKey == "LastModified" && x.Timestamp >= timeLimit);

            await foreach (TableEntity entity in query)
            {
                modifiedPartitions.Add(entity.RowKey);
            }

            sw.Stop();
            _log.LogInformation($"Identifying {modifiedPartitions.Count} modified partitions since {timeLimit.UtcDateTime} took {sw.ElapsedMilliseconds:n0}ms");

            return modifiedPartitions.ToArray();
            */
            return Array.Empty<string>();
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
            /*
            await _metadataTable.DeleteEntityAsync(partitionKey, rowKey);
            */
        }

        /// <summary>
        /// Deletes all duplicate request items 
        /// </summary>
        public async Task RemoveOldDuplicateRequests()
        {
            /*
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
            */
        }
    }
}
