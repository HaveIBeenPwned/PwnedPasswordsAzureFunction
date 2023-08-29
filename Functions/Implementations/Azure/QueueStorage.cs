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
        await _transactionQueueClient.SendMessageAsync(JsonSerializer.Serialize(entry), cancellationToken).ConfigureAwait(false);
        _log.LogInformation("Subscription {SubscriptionId} successfully queued transaction {TransactionId} for processing.", entry.SubscriptionId, entry.TransactionId);
    }

    /// <summary>
    /// Push a append job to the queue
    /// </summary>
    /// <param name="append">The append request to push to the queue</param>
    public async Task PushPasswordsAsync(PasswordEntryBatch batch, CancellationToken cancellationToken = default)
    {
        await _queueClient.SendMessageAsync(JsonSerializer.Serialize(batch), cancellationToken).ConfigureAwait(false);
        foreach (KeyValuePair<string, List<HashEntry>> item in batch.SHA1Entries)
        {
            foreach (HashEntry entry in item.Value)
            {
                _log.LogInformation("Subscription {SubscriptionId} successfully queued SHA1 hash {SHA1} as part af transaction {TransactionId}", batch.SubscriptionId, entry.HashText, batch.TransactionId);
            }
        }
        foreach (KeyValuePair<string, List<HashEntry>> item in batch.NTLMEntries)
        {
            foreach (HashEntry entry in item.Value)
            {
                _log.LogInformation("Subscription {SubscriptionId} successfully queued NTLM hash {NTLM} as part af transaction {TransactionId}", batch.SubscriptionId, entry.HashText, batch.TransactionId);
            }
        }
    }
}
