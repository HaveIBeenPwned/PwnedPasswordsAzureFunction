namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure;

public class QueueStorage : IQueueStorage
{
    private readonly ILogger _log;
    private readonly QueueClient _queueClient;
    private readonly QueueClient _transactionQueueClient;

    public QueueStorage(IOptions<QueueStorageOptions> storageQueueOptions, ILogger<QueueStorage> log, QueueServiceClient serviceClient)
    {
        _log = log;
        _queueClient = serviceClient.GetQueueClient($"{storageQueueOptions.Value.Namespace}-ingestion");
        _transactionQueueClient = serviceClient.GetQueueClient($"{storageQueueOptions.Value.Namespace}-transaction");
        _queueClient.CreateIfNotExists();
        _transactionQueueClient.CreateIfNotExists();
    }

    public async Task PushTransactionAsync(QueueTransactionEntry entry, CancellationToken cancellationToken = default)
    {
        await _transactionQueueClient.SendMessageAsync(JsonSerializer.Serialize(entry), cancellationToken);
        _log.LogInformation("Subscription {SubscriptionId} successfully queued transaction {TransactionId} for processing.", entry.SubscriptionId, entry.TransactionId);
    }

    /// <summary>
    /// Push a append job to the queue
    /// </summary>
    /// <param name="append">The append request to push to the queue</param>
    public async Task PushPasswordsAsync(QueuePasswordEntry[] entries, CancellationToken cancellationToken = default)
    {
        await _queueClient.SendMessageAsync(JsonSerializer.Serialize(entries), cancellationToken).ConfigureAwait(false);
        foreach (QueuePasswordEntry? entry in entries)
        {
            _log.LogInformation("Subscription {SubscriptionId} successfully queued SHA1 hash {SHA1} as part af transaction {TransactionId}", entry.SubscriptionId, entry.SHA1Hash, entry.TransactionId);
        }
    }
}
