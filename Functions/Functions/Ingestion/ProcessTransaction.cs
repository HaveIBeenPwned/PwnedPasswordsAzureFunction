// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion
{
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
        public async Task Run([QueueTrigger("%TableNamespace%-transaction", Connection = "PwnedPasswordsConnectionString")] QueueTransactionEntry item, CancellationToken cancellationToken)
        {
            Activity.Current?.AddTag("SubscriptionId", item.SubscriptionId).AddTag("TransactionId", item.TransactionId);
            try
            {
                if (await _tableStorage.IsTransactionConfirmedAsync(item.SubscriptionId, item.TransactionId, cancellationToken).ConfigureAwait(false))
                {
                    _log.LogInformation("Subscription {SubscriptionId} started processing for transaction {TransactionId}. Fetching transaction entries.", item.SubscriptionId, item.TransactionId);
                    using (Stream stream = await _fileStorage.GetIngestionFileAsync(item.TransactionId, cancellationToken).ConfigureAwait(false))
                    {
                        await foreach (PwnedPasswordsIngestionValue? entry in JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(stream, cancellationToken: cancellationToken))
                        {
                            if (entry != null)
                            {
                                var queueEntry = new QueuePasswordEntry { SubscriptionId = item.SubscriptionId, TransactionId = item.TransactionId, SHA1Hash = entry.SHA1Hash, NTLMHash = entry.NTLMHash, Prevalence = entry.Prevalence };
                                await _queueStorage.PushPasswordAsync(queueEntry, cancellationToken).ConfigureAwait(false);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                _log.LogError(e, "Error processing transaction with id = {TransactionId} for subscription {SubscriptionId}.", item.TransactionId, item.SubscriptionId);
            }
        }
    }
}
