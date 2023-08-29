// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO.Pipelines;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

public class ProcessPwnedPasswordEntryBatch
{
    private readonly ILogger<ProcessPwnedPasswordEntryBatch> _log;
    private readonly ITableStorage _tableStorage;
    private readonly IFileStorage _blobStorage;

    /// <summary>
    /// Pwned Passwords - Append handler
    /// </summary>
    /// <param name="blobStorage">The Blob storage</param>
    public ProcessPwnedPasswordEntryBatch(ILogger<ProcessPwnedPasswordEntryBatch> log, ITableStorage tableStorage, IFileStorage blobStorage)
    {
        _log = log;
        _tableStorage = tableStorage;
        _blobStorage = blobStorage;
    }

    [FunctionName("ProcessAppendQueueItem")]
    public async Task Run([QueueTrigger("%TableNamespace%-ingestion", Connection = "PwnedPasswordsConnectionString")] byte[] queueItem, CancellationToken cancellationToken)
    {
        PasswordEntryBatch? batch = JsonSerializer.Deserialize<PasswordEntryBatch>(Encoding.UTF8.GetString(queueItem));
        if (batch != null)
        {
            // Let's set some activity tags and log scopes so we have event correlation in our logs!
            Activity.Current?.AddTag("SubscriptionId", batch.SubscriptionId).AddTag("TransactionId", batch.TransactionId);
            foreach (KeyValuePair<string, List<HashEntry>> prefixBatch in batch.SHA1Entries)
            {
                await _tableStorage.MarkHashPrefixAsModified(prefixBatch.Key).ConfigureAwait(false);
                await UpdateHashfile(batch, prefixBatch.Key, HashType.SHA1, prefixBatch.Value).ConfigureAwait(false);
            }

            foreach (KeyValuePair<string, List<HashEntry>> prefixBatch in batch.NTLMEntries)
            {
                await _tableStorage.MarkHashPrefixAsModified(prefixBatch.Key).ConfigureAwait(false);
                await UpdateHashfile(batch, prefixBatch.Key, HashType.NTLM, prefixBatch.Value).ConfigureAwait(false);
            }
        }

        async Task UpdateHashfile(PasswordEntryBatch batch, string prefix, HashType mode, List<HashEntry> batchEntries, CancellationToken cancellationToken = default)
        {
            bool blobUpdated = false;
            while (!blobUpdated)
            {
                try
                {
                    blobUpdated = await ParseAndUpdateHashFile(batch, prefix, mode, batchEntries, cancellationToken).ConfigureAwait(false);
                    if (!blobUpdated)
                    {
                        _log.LogWarning("Subscription {SubscriptionId} failed to update {Mode} blob {HashPrefix} as part of transaction {TransactionId}! Will retry!", batch.SubscriptionId, mode, prefix, batch.TransactionId);
                    }
                }
                catch (FileNotFoundException)
                {
                    _log.LogError("Subscription {SubscriptionId} is unable to find a {Mode} hash file with prefix {prefix} as part of transaction {TransactionId}. Something is wrong as this shouldn't happen!", batch.SubscriptionId, mode, prefix, batch.TransactionId);
                    return;
                }
            }

            _log.LogInformation("Subscription {SubscriptionId} successfully updated {Mode} blob {HashPrefix} as part of transaction {TransactionId}!", batch.SubscriptionId, mode, prefix, batch.TransactionId);
        }
    }

    private async Task<bool> ParseAndUpdateHashFile(PasswordEntryBatch batch, string prefix, HashType mode, List<HashEntry> batchEntries, CancellationToken cancellationToken = default)
    {
        PwnedPasswordsFile blobFile = await _blobStorage.GetHashFileAsync(prefix, mode, cancellationToken).ConfigureAwait(false);

        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
        SortedDictionary<string, int> hashes = new();
        await foreach (HashEntry item in HashEntry.ParseTextHashEntries(prefix, PipeReader.Create(blobFile.Content)).ConfigureAwait(false))
        {
            hashes.Add(item.HashText[5..], item.Prevalence);
        }

        // We now have a sorted dictionary with the hashes for this prefix.
        // Let's add or update the suffixes with the prevalence counts.
        foreach (HashEntry item in batchEntries)
        {
            string suffix = item.HashText[5..];
            if (hashes.ContainsKey(suffix))
            {
                hashes[suffix] = hashes[suffix] + item.Prevalence;
                _log.LogInformation("Subscription {SubscriptionId} updating suffix {HashSuffix} in {Mode} blob {HashPrefix} from {PrevalenceBefore} to {PrevalenceAfter} as part of transaction {TransactionId}!", batch.SubscriptionId, suffix, mode, prefix, hashes[suffix] - item.Prevalence, hashes[suffix], batch.TransactionId);
            }
            else
            {
                hashes.Add(suffix, item.Prevalence);
                _log.LogInformation("Subscription {SubscriptionId} adding new suffix {HashSuffix} to {Mode} blob {HashPrefix} with {Prevalence} as part of transaction {TransactionId}!", batch.SubscriptionId, suffix, mode, prefix, item.Prevalence, batch.TransactionId);
            }
        }

        // Now let's try to update the current blob with the new prevalence count!
        return await _blobStorage.UpdateHashFileAsync(prefix, mode, hashes, blobFile.ETag, cancellationToken).ConfigureAwait(false);
    }
}
