using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Azure.Storage.Queues;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure
{
    public class QueueStorage : IQueueStorage
    {
        private readonly ILogger _log;
        private readonly QueueClient _queueClient;
        private readonly QueueClient _transactionQueueClient;
        private readonly SemaphoreSlim _semaphore = new(1);
        private volatile bool _initialized;

        public QueueStorage(IOptions<QueueStorageOptions> storageQueueOptions, ILogger<QueueStorage> log)
        {
            _log = log;
            QueueClientOptions options = new() { MessageEncoding = QueueMessageEncoding.Base64 };
            _queueClient = new QueueClient(storageQueueOptions.Value.ConnectionString, $"{storageQueueOptions.Value.Namespace}-ingestion", options);
            _transactionQueueClient = new QueueClient(storageQueueOptions.Value.ConnectionString, $"{storageQueueOptions.Value.Namespace}-transaction", options);
        }

        public async Task PushTransactionAsync(QueueTransactionEntry entry, CancellationToken cancellationToken = default)
        {
            await InitializeIfNeeded().ConfigureAwait(false);
            await _transactionQueueClient.SendMessageAsync(JsonSerializer.Serialize(entry), cancellationToken);
            _log.LogInformation("Subscription {SubscriptionId} successfully queued transaction {TransactionId} for processing.", entry.SubscriptionId, entry.TransactionId);
        }

        /// <summary>
        /// Push a append job to the queue
        /// </summary>
        /// <param name="append">The append request to push to the queue</param>
        public async Task PushPasswordsAsync(List<QueuePasswordEntry> entries, CancellationToken cancellationToken = default)
        {
            await InitializeIfNeeded().ConfigureAwait(false);
            await _queueClient.SendMessageAsync(JsonSerializer.Serialize(entries), cancellationToken).ConfigureAwait(false);
            foreach (var entry in entries)
            {
                _log.LogInformation("Subscription {SubscriptionId} successfully queued SHA1 hash {SHA1} as part af transaction {TransactionId}", entry.SubscriptionId, entry.SHA1Hash, entry.TransactionId);
            }
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
