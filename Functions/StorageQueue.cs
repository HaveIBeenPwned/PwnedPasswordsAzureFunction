using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Azure.Storage.Queues;

using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace HaveIBeenPwned.PwnedPasswords
{
    public class StorageQueue
    {
        private readonly ILogger _log;
        private readonly QueueClient _queueClient;
        private readonly QueueClient _transactionQueueClient;
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1);
        private volatile bool _initialized;

        internal string IngestionQueueName { get; }
        internal string TransactionQueueName { get; }

        public StorageQueue(IConfiguration configuration, ILogger<StorageQueue> log)
        {
            _log = log;
            string? storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            IngestionQueueName = $"{configuration["TableNamespace"]}-ingestion";
            TransactionQueueName = $"{configuration["TableNamespace"]}-transaction";

            QueueClientOptions options = new QueueClientOptions { MessageEncoding = QueueMessageEncoding.Base64 };
            _queueClient = new QueueClient(storageConnectionString, IngestionQueueName, options);
            _transactionQueueClient = new QueueClient(storageConnectionString, TransactionQueueName, options);
        }

        public async Task PushTransaction(string subscriptionId, string transactionId)
        {
            await InitializeIfNeeded().ConfigureAwait(false);
            await _transactionQueueClient.SendMessageAsync(JsonSerializer.Serialize(new QueueTransactionEntry { SubscriptionId = subscriptionId, TransactionId = transactionId }));
            _log.LogInformation("Subscription {SubscriptionId} successfully queued transaction {TransactionId} for processing.", subscriptionId, transactionId);
        }

        /// <summary>
        /// Push a append job to the queue
        /// </summary>
        /// <param name="append">The append request to push to the queue</param>
        public async Task PushPassword(string subscriptionId, AppendDataEntity append)
        {
            await InitializeIfNeeded().ConfigureAwait(false);
            await _queueClient.SendMessageAsync(JsonSerializer.Serialize(new AppendQueueItem { SubscriptionId = subscriptionId, TransactionId = append.PartitionKey, SHA1Hash = append.RowKey, NTLMHash = append.NTLMHash, Prevalence = append.Prevalence })).ConfigureAwait(false);
            _log.LogInformation("Subscription {SubscriptionId} successfully queued SHA1 hash {SHA1} as part af transaction {TransactionId}", subscriptionId, append.RowKey, append.PartitionKey);
        }

        private async Task InitializeIfNeeded()
        {
            if (!_initialized)
            {
                await _semaphore.WaitAsync().ConfigureAwait(false);
                if (!_initialized)
                {
                    await Task.WhenAll(_queueClient.CreateIfNotExistsAsync(), _transactionQueueClient.CreateIfNotExistsAsync()).ConfigureAwait(false);
                    _initialized = true;
                }

                _semaphore.Release();
            }
        }
    }
}
