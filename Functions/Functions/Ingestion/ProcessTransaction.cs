// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System.Threading.Channels;

using Newtonsoft.Json.Linq;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

public class ProcessTransaction
{
    private readonly ILogger<ProcessTransaction> _log;
    private readonly ITableStorage _tableStorage;
    private readonly IQueueStorage _queueStorage;
    private readonly IFileStorage _fileStorage;

    /// <summary>
    /// Pwned Passwords - Append handler
    /// </summary>
    /// <param name="blobStorage">The Blob storage</param>
    public ProcessTransaction(ILogger<ProcessTransaction> log, ITableStorage tableStorage, IQueueStorage queueStorage, IFileStorage fileStorage)
    {
        _log = log;
        _tableStorage = tableStorage;
        _queueStorage = queueStorage;
        _fileStorage = fileStorage;
    }

    [FunctionName("ProcessTransactionQueueItem")]
    public async Task Run([QueueTrigger("%TableNamespace%-transaction", Connection = "PwnedPasswordsConnectionString")] byte[] queueItem, CancellationToken cancellationToken)
    {
        SortedDictionary<string, List<HashEntry>> ntlmEntries = new();
        SortedDictionary<string, List<HashEntry>> sha1Entries = new();

        QueueTransactionEntry? item = JsonSerializer.Deserialize<QueueTransactionEntry>(Encoding.UTF8.GetString(queueItem)) ?? throw new ArgumentException("Queue item contains no data.", nameof(queueItem));
        Activity.Current?.AddTag("SubscriptionId", item.SubscriptionId).AddTag("TransactionId", item.TransactionId);
        try
        {
            if (await _tableStorage.IsTransactionConfirmedAsync(item.SubscriptionId, item.TransactionId, cancellationToken).ConfigureAwait(false))
            {
                _log.LogInformation("Subscription {SubscriptionId} started processing for transaction {TransactionId}. Fetching transaction entries.", item.SubscriptionId, item.TransactionId);
                using (Stream stream = await _fileStorage.GetIngestionFileAsync(item.TransactionId, cancellationToken).ConfigureAwait(false))
                {
                    await foreach (PwnedPasswordsIngestionValue? entry in JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(stream, cancellationToken: cancellationToken).ConfigureAwait(false))
                    {
                        if (entry != null)
                        {
                            entry.SHA1Hash = entry.SHA1Hash.ToUpperInvariant();
                            string sha1Prefix = entry.SHA1Hash[..5];
                            if (!sha1Entries.TryGetValue(sha1Prefix, out List<HashEntry>? sha1Values))
                            {
                                sha1Values = new List<HashEntry>();
                                sha1Entries[sha1Prefix] = sha1Values;
                            }

                            if (HashEntry.TryParseFromText(entry.SHA1Hash, entry.Prevalence, out HashEntry sha1HashEntry))
                            {
                                sha1Values.Add(sha1HashEntry);
                            }

                            entry.NTLMHash = entry.NTLMHash.ToUpperInvariant();
                            string ntlmPrefix = entry.NTLMHash[..5];
                            if (!ntlmEntries.TryGetValue(ntlmPrefix, out List<HashEntry>? ntlmValues))
                            {
                                ntlmValues = new List<HashEntry>();
                                ntlmEntries[ntlmPrefix] = ntlmValues;
                            }

                            if (HashEntry.TryParseFromText(entry.NTLMHash, entry.Prevalence, out HashEntry ntlmHashEntry))
                            {
                                ntlmValues.Add(ntlmHashEntry);
                            }
                        }
                    }

                    int num = 0;
                    var batch = new PasswordEntryBatch
                    {
                        SubscriptionId = item.SubscriptionId,
                        TransactionId = item.TransactionId,
                    };

                    foreach (KeyValuePair<string, List<HashEntry>> entry in sha1Entries)
                    {
                        if (num >= 500)
                        {
                            await QueueHashBatchForProcessing(batch).ConfigureAwait(false);
                            num = 0;
                        }

                        batch.SHA1Entries.Add(entry.Key, entry.Value);
                        num += entry.Value.Count;
                    }

                    foreach (KeyValuePair<string, List<HashEntry>> entry in ntlmEntries)
                    {
                        if (num >= 500)
                        {
                            await QueueHashBatchForProcessing(batch).ConfigureAwait(false);
                            num = 0;
                        }

                        batch.NTLMEntries.Add(entry.Key, entry.Value);
                        num += entry.Value.Count;
                    }

                    if (num > 0)
                    {
                        await QueueHashBatchForProcessing(batch).ConfigureAwait(false);
                    }
                }
            }
        }
        catch (Exception e)
        {
            _log.LogError(e, "Error processing transaction with id = {TransactionId} for subscription {SubscriptionId}.", item.TransactionId, item.SubscriptionId);
        }
    }

    private async Task QueueHashBatchForProcessing(PasswordEntryBatch batch, CancellationToken cancellationToken = default)
    {
        await _queueStorage.PushPasswordsAsync(batch, cancellationToken).ConfigureAwait(false);
        batch.SHA1Entries.Clear();
        batch.NTLMEntries.Clear();
    }
}
