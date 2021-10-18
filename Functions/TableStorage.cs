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
using System.Threading;
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
        private SemaphoreSlim _semaphore = new SemaphoreSlim(1);

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
                await _semaphore.WaitAsync();
                if (!_initialized)
                {
                    await Task.WhenAll(
                        _transactionTable.CreateIfNotExistsAsync(),
                        _dataTable.CreateIfNotExistsAsync(),
                        _hashDataTable.CreateIfNotExistsAsync(),
                        _cachePurgeTable.CreateIfNotExistsAsync());
                    _initialized = true;
                }

                _semaphore.Release();
            }
        }

        public async Task<string> InsertAppendData(PwnedPasswordAppend[] data, string subscriptionId)
        {
            await InitializeIfNeededAsync();
            string transactionId = Guid.NewGuid().ToString();
            await _transactionTable.AddEntityAsync(new AppendTransactionEntity { PartitionKey = subscriptionId, RowKey = transactionId, Confirmed = false });
            _log.LogInformation("Subscription {SubscriptionId} created a new transaction with id = {TransactionId}.", subscriptionId, transactionId);

            List<TableTransactionAction> tableTransactions = new List<TableTransactionAction>(100);
            List<Task> submitTasks = new List<Task>();
            for (int i = 0; i < data.Length; i++)
            {
                PwnedPasswordAppend? item = data[i];
                tableTransactions.Add(new TableTransactionAction(TableTransactionActionType.Add, new AppendDataEntity { PartitionKey = transactionId, RowKey = item.SHA1Hash, NTLMHash = item.NTLMHash, Prevalence = item.Prevalence }));
                if(tableTransactions.Count == 100)
                {
                    submitTasks.Add(_dataTable.SubmitTransactionAsync(tableTransactions));
                    tableTransactions = new List<TableTransactionAction>(100);
                }
            }

            if(tableTransactions.Count > 0)
            {
                submitTasks.Add(_dataTable.SubmitTransactionAsync(tableTransactions));
            }

            await Task.WhenAll(submitTasks).ConfigureAwait(false);
            _log.LogInformation("Subscription {SubscriptionId} added {NumEntries} entries into transaction {TransactionId}", subscriptionId, data.Length, transactionId);
            return transactionId;
        }

        public async Task<IActionResult> ConfirmAppendDataAsync(string subscriptionId, string transactionId, StorageQueue storageQueue)
        {
            await InitializeIfNeededAsync().ConfigureAwait(false);
            try
            {
                Response<AppendTransactionEntity> transactionEntityResponse = await _transactionTable.GetEntityAsync<AppendTransactionEntity>(subscriptionId, transactionId).ConfigureAwait(false);
                if (!transactionEntityResponse.Value.Confirmed)
                {
                    transactionEntityResponse.Value.Confirmed = true;
                    var updateResponse = await _transactionTable.UpdateEntityAsync(transactionEntityResponse.Value, transactionEntityResponse.Value.ETag).ConfigureAwait(false);
                    _log.LogInformation("Subscription {SubscriptionId} successfully confirmed transaction {TransactionId}. Queueing data for blob updates.", subscriptionId, transactionId);
                    await storageQueue.PushTransaction(subscriptionId, transactionId);
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

        public async Task ProcessTransactionAsync(string subscriptionId, string transactionId, StorageQueue storageQueue)
        {
            await InitializeIfNeededAsync().ConfigureAwait(false);
            try
            {
                Response<AppendTransactionEntity> transactionEntityResponse = await _transactionTable.GetEntityAsync<AppendTransactionEntity>(subscriptionId, transactionId).ConfigureAwait(false);
                if (transactionEntityResponse.Value.Confirmed)
                {
                    _log.LogInformation("Subscription {SubscriptionId} started processing for transaction {TransactionId}. Queueing data for blob updates.", subscriptionId, transactionId);

                    AsyncPageable<AppendDataEntity>? transactionDataResponse = _dataTable.QueryAsync<AppendDataEntity>(x => x.PartitionKey == transactionId);
                    await foreach (AppendDataEntity? item in transactionDataResponse)
                    {
                        // Send all the entities to the queue for processing.
                        await storageQueue.PushPassword(subscriptionId, item);
                    }
                }
            }
            catch (RequestFailedException e)
            {
                _log.LogError(e, "Error processing transaction with id = {TransactionId} for subscription {SubscriptionId}.", transactionId, subscriptionId);
            }
        }

        /// <summary>
        /// Updates the prevalence for the given hash by a specified amount
        /// </summary>
        /// <param name="append">The append request to process</param>
        public async Task UpdateHashTable(AppendQueueItem append)
        {
            await InitializeIfNeededAsync().ConfigureAwait(false);
            string partitionKey = append.SHA1Hash.Substring(0, 5);
            string rowKey = append.SHA1Hash.Substring(5);

            try
            {
                while (!await UpsertPwnedPasswordEntity(append).ConfigureAwait(false))
                {
                }

                await _cachePurgeTable.UpsertEntityAsync(new TableEntity($"{DateTime.UtcNow.Year}-{DateTime.UtcNow.Month}-{DateTime.UtcNow.Day}", partitionKey)).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                _log.LogError(e, "An error occured");
                throw;
            }
        }

        private async Task<bool> UpsertPwnedPasswordEntity(AppendQueueItem append)
        {
            string partitionKey = append.SHA1Hash.Substring(0, 5);
            string rowKey = append.SHA1Hash.Substring(5);

            try
            {
                try
                {
                    var entityResponse = await _hashDataTable.GetEntityAsync<PwnedPasswordEntity>(partitionKey, rowKey).ConfigureAwait(false);
                    var pwnedPassword = entityResponse.Value;
                    pwnedPassword.Prevalence += append.Prevalence;
                    await _hashDataTable.UpdateEntityAsync(pwnedPassword, pwnedPassword.ETag).ConfigureAwait(false);
                    _log.LogInformation("Subscription {SubscriptionId} updated SHA1 entry {SHA1} from {PrevalenceBefore} to {PrevalenceAfter} as part of transaction {TransactionId}", append.SubscriptionId, append.SHA1Hash, pwnedPassword.Prevalence - append.Prevalence, pwnedPassword.Prevalence, append.TransactionId);
                }
                // If the item doesn't exist
                catch (RequestFailedException e) when (e.Status == StatusCodes.Status404NotFound)
                {
                    var insertSw = Stopwatch.StartNew();
                    await _hashDataTable.AddEntityAsync(new PwnedPasswordEntity { PartitionKey = partitionKey, RowKey = rowKey, NTLMHash = append.NTLMHash, Prevalence = append.Prevalence }).ConfigureAwait(false);
                    _log.LogInformation("Subscription {SubscriptionId} added new SHA1 entry {SHA1} with {Prevalence} as part of transaction {TransactionId}", append.SubscriptionId, append.SHA1Hash, append.Prevalence, append.TransactionId);
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
        /// Get the modified blobs since yesterday
        /// </summary>
        /// <returns>List of partition keys which have been modified</returns>
        public async Task<string[]> GetModifiedBlobs()
        {
            var yesterday = DateTime.UtcNow.AddDays(0);
            var results = _cachePurgeTable.QueryAsync<TableEntity>(x => x.PartitionKey == $"{yesterday.Year}-{yesterday.Month}-{yesterday.Day}");
            List<string> prefixes = new List<string>();
            await foreach(TableEntity? item in results)
            {
                if(item != null)
                {
                    prefixes.Add(item.RowKey);
                }
            }

            return prefixes.ToArray();
        }
    }
}
