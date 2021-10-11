using System.Text.Json;
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
        internal string IngestionQueueName { get; }
        private bool _initialized;

        public StorageQueue(IConfiguration configuration, ILogger<StorageQueue> log)
        {
            _log = log;
            string? storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            IngestionQueueName = $"{configuration["TableNamespace"]}-ingestion";
            
            _queueClient = new QueueClient(storageConnectionString, IngestionQueueName, new QueueClientOptions { MessageEncoding = QueueMessageEncoding.Base64 });
        }

        /// <summary>
        /// Push a append job to the queue
        /// </summary>
        /// <param name="append">The append request to push to the queue</param>
        public async Task PushPassword(string subscriptionId, AppendDataEntity append)
        {
            await InitializeIfNeeded();
            await _queueClient.SendMessageAsync(JsonSerializer.Serialize(new AppendQueueItem { SubscriptionId = subscriptionId, TransactionId = append.PartitionKey, SHA1Hash = append.RowKey, NTLMHash = append.NTLMHash, Prevalence = append.Prevalence }));
        }

        private async Task InitializeIfNeeded()
        {
            if (!_initialized)
            {
                await _queueClient.CreateIfNotExistsAsync();
                _initialized = true;
            }
        }
    }
}
