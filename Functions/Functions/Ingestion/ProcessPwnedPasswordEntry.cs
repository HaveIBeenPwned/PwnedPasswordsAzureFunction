// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System.Threading.Channels;

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
        var batch = JsonSerializer.Deserialize<PasswordEntryBatch>(Encoding.UTF8.GetString(queueItem));
        if (batch != null)
        {
            // Let's set some activity tags and log scopes so we have event correlation in our logs!
            Activity.Current?.AddTag("SubscriptionId", batch.SubscriptionId).AddTag("TransactionId", batch.TransactionId);
            foreach (var item in batch.PasswordEntries)
            {
                while (!await _tableStorage.AddOrIncrementHashEntry(batch, item, cancellationToken).ConfigureAwait(false))
                {
                }

                string prefix = batch.Prefix;
                string suffix = item.SHA1Hash[5..];

                await _tableStorage.MarkHashPrefixAsModified(prefix, cancellationToken).ConfigureAwait(false);

                bool blobUpdated = false;
                while (!blobUpdated)
                {
                    try
                    {
                        blobUpdated = await ParseAndUpdateHashFile(batch, cancellationToken).ConfigureAwait(false);
                        if (!blobUpdated)
                        {
                            _log.LogWarning("Subscription {SubscriptionId} failed to updated blob {HashPrefix} as part of transaction {TransactionId}! Will retry!", batch.SubscriptionId, prefix, batch.TransactionId);
                        }
                    }
                    catch (FileNotFoundException)
                    {
                        _log.LogError("Subscription {SubscriptionId} is unable to find a hash file with prefix {prefix} as part of transaction {TransactionId}. Something is wrong as this shouldn't happen!", batch.SubscriptionId, prefix, batch.TransactionId);
                        return;
                    }
                }

                _log.LogInformation("Subscription {SubscriptionId} successfully updated blob {HashPrefix} as part of transaction {TransactionId}!", batch.SubscriptionId, prefix, batch.TransactionId);
            }
        }
    }

    private async Task<bool> ParseAndUpdateHashFile(PasswordEntryBatch batch, CancellationToken cancellationToken = default)
    {
        PwnedPasswordsFile blobFile = await _blobStorage.GetHashFileAsync(batch.Prefix, cancellationToken).ConfigureAwait(false);

        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
        SortedDictionary<string, int> hashes = ParseHashFile(blobFile);

        // We now have a sorted dictionary with the hashes for this prefix.
        // Let's add or update the suffixes with the prevalence counts.
        foreach (var item in batch.PasswordEntries)
        {
            string suffix = item.SHA1Hash[5..];
            if (hashes.ContainsKey(suffix))
            {
                hashes[suffix] = hashes[suffix] + item.Prevalence;
                _log.LogInformation("Subscription {SubscriptionId} updating suffix {HashSuffix} in blob {HashPrefix} from {PrevalenceBefore} to {PrevalenceAfter} as part of transaction {TransactionId}!", batch.SubscriptionId, suffix, batch.Prefix, hashes[suffix] - item.Prevalence, hashes[suffix], batch.TransactionId);
            }
            else
            {
                hashes.Add(suffix, item.Prevalence);
                _log.LogInformation("Subscription {SubscriptionId} adding new suffix {HashSuffix} to blob {HashPrefix} with {Prevalence} as part of transaction {TransactionId}!", batch.SubscriptionId, suffix, batch.Prefix, item.Prevalence, batch.TransactionId);
            }
        }

        // Now let's try to update the current blob with the new prevalence count!
        return await _blobStorage.UpdateHashFileAsync(batch.Prefix, hashes, blobFile.ETag, cancellationToken).ConfigureAwait(false);
    }

    private static SortedDictionary<string, int> ParseHashFile(PwnedPasswordsFile blobFile)
    {
        var hashes = new SortedDictionary<string, int>();
        using (var reader = new StreamReader(blobFile.Content))
        {
            string? hashLine = reader.ReadLine();
            while (hashLine != null)
            {
                // Let's make sure we can parse this as a proper hash!
                if (!string.IsNullOrEmpty(hashLine) && hashLine.Length >= 37 && hashLine[35] == ':' && int.TryParse(hashLine[36..], out int currentPrevalence))
                {
                    hashes.Add(hashLine[..35], currentPrevalence);
                }

                hashLine = reader.ReadLine();
            }
        }

        return hashes;
    }
}
