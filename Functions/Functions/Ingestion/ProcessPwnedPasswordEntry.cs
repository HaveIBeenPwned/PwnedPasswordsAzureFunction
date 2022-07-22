// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System.Threading.Channels;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

public class ProcessPwnedPasswordEntry
{
    private readonly ILogger<ProcessPwnedPasswordEntry> _log;
    private readonly ITableStorage _tableStorage;
    private readonly IFileStorage _blobStorage;
    private readonly IQueueStorage _queueStorage;

    /// <summary>
    /// Pwned Passwords - Append handler
    /// </summary>
    /// <param name="blobStorage">The Blob storage</param>
    public ProcessPwnedPasswordEntry(ILogger<ProcessPwnedPasswordEntry> log, ITableStorage tableStorage, IFileStorage blobStorage, IQueueStorage queueStorage)
    {
        _log = log;
        _tableStorage = tableStorage;
        _blobStorage = blobStorage;
        _queueStorage = queueStorage;
    }

    [FunctionName("ProcessAppendQueueItem")]
    public async Task Run([QueueTrigger("%TableNamespace%-ingestion", Connection = "PwnedPasswordsConnectionString")] byte[] queueItem, CancellationToken cancellationToken)
    {
        var items = JsonSerializer.Deserialize<QueuePasswordEntry[]>(Encoding.UTF8.GetString(queueItem));
        if (items != null)
        {
            Channel<QueuePasswordEntry> channel = Channel.CreateBounded<QueuePasswordEntry>(new BoundedChannelOptions(Startup.Parallelism) { FullMode = BoundedChannelFullMode.Wait, SingleReader = false, SingleWriter = true });
            Task[] queueTasks = new Task[Startup.Parallelism];
            for (int i = 0; i < queueTasks.Length; i++)
            {
                queueTasks[i] = ProcessQueueItem(channel);
            }

            foreach (QueuePasswordEntry item in items)
            {
                await channel.Writer.WriteAsync(item);
            }

            channel.Writer.TryComplete();
            await Task.WhenAll(queueTasks);
        }
    }

    private async Task ProcessQueueItem(Channel<QueuePasswordEntry> channel, CancellationToken cancellationToken = default)
    {
        while (await channel.Reader.WaitToReadAsync(cancellationToken))
        {
            if (channel.Reader.TryRead(out QueuePasswordEntry? item) && item != null)
            {
                await ProcessPasswordEntry(item, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ProcessPasswordEntry(QueuePasswordEntry item, CancellationToken cancellationToken)
    {
        // Let's set some activity tags and log scopes so we have event correlation in our logs!
        Activity.Current?.AddTag("SubscriptionId", item.SubscriptionId).AddTag("TransactionId", item.TransactionId);
        while (!await _tableStorage.AddOrIncrementHashEntry(item.SubscriptionId, item.TransactionId, new PwnedPasswordsIngestionValue { SHA1Hash = item.SHA1Hash, NTLMHash = item.NTLMHash, Prevalence = item.Prevalence }, cancellationToken).ConfigureAwait(false))
        {
        }

        string prefix = item.SHA1Hash[..5];
        string suffix = item.SHA1Hash[5..];

        await _tableStorage.MarkHashPrefixAsModified(prefix, cancellationToken).ConfigureAwait(false);

        bool blobUpdated = false;
        while (!blobUpdated)
        {
            try
            {
                blobUpdated = await ParseAndUpdateHashFile(item, prefix, suffix, cancellationToken).ConfigureAwait(false);
                if (!blobUpdated)
                {
                    _log.LogWarning("Subscription {SubscriptionId} failed to updated blob {HashPrefix} as part of transaction {TransactionId}! Will retry!", item.SubscriptionId, prefix, item.TransactionId);
                }
            }
            catch (FileNotFoundException)
            {
                _log.LogError("Subscription {SubscriptionId} is unable to find a hash file with prefix {prefix} as part of transaction {TransactionId}. Something is wrong as this shouldn't happen!", item.SubscriptionId, prefix, item.TransactionId);
                return;
            }
        }

        _log.LogInformation("Subscription {SubscriptionId} successfully updated blob {HashPrefix} as part of transaction {TransactionId}!", item.SubscriptionId, prefix, item.TransactionId);
    }

    private async Task<bool> ParseAndUpdateHashFile(QueuePasswordEntry item, string prefix, string suffix, CancellationToken cancellationToken = default)
    {
        PwnedPasswordsFile blobFile = await _blobStorage.GetHashFileAsync(prefix, cancellationToken).ConfigureAwait(false);

        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
        SortedDictionary<string, int> hashes = ParseHashFile(blobFile);

        // We now have a sorted dictionary with the hashes for this prefix.
        // Let's add or update the suffix with the prevalence count.
        if (hashes.ContainsKey(suffix))
        {
            hashes[suffix] = hashes[suffix] + item.Prevalence;
            _log.LogInformation("Subscription {SubscriptionId} updating suffix {HashSuffix} in blob {HashPrefix} from {PrevalenceBefore} to {PrevalenceAfter} as part of transaction {TransactionId}!", item.SubscriptionId, suffix, prefix, hashes[suffix] - item.Prevalence, hashes[suffix], item.TransactionId);
        }
        else
        {
            hashes.Add(suffix, item.Prevalence);
            _log.LogInformation("Subscription {SubscriptionId} adding new suffix {HashSuffix} to blob {HashPrefix} with {Prevalence} as part of transaction {TransactionId}!", item.SubscriptionId, suffix, prefix, item.Prevalence, item.TransactionId);
        }

        // Now let's try to update the current blob with the new prevalence count!
        return await _blobStorage.UpdateHashFileAsync(prefix, hashes, blobFile.ETag, cancellationToken).ConfigureAwait(false);
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
