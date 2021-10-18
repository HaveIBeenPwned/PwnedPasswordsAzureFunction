// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using HaveIBeenPwned.PwnedPasswords.Models;
using System.Collections.Generic;
using System.IO;

namespace HaveIBeenPwned.PwnedPasswords.Functions
{
    public class Append
    {
        private const string SubscriptionIdHeaderKey = "Api-Subscription-Id";
        private readonly ILogger<Append> _log;
        private readonly TableStorage _tableStorage;
        private readonly StorageQueue _queueStorage;
        private readonly IStorageService _blobStorage;
        private readonly Cloudflare _cloudflare;

        /// <summary>
        /// Pwned Passwords - Append handler
        /// </summary>
        /// <param name="blobStorage">The Blob storage</param>
        public Append(ILogger<Append> log, TableStorage tableStorage, StorageQueue queueStorage, IStorageService blobStorage, Cloudflare cloudflare)
        {
            _log = log;
            _tableStorage = tableStorage;
            _queueStorage = queueStorage;
            _blobStorage = blobStorage;
            _cloudflare = cloudflare;
        }

        /// <summary>
        /// Handle a request to /range/append
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns>Response to the requesting client</returns>
        [FunctionName("AppendPwnedPassword")]
        public async Task<IActionResult> AppendData([HttpTrigger(AuthorizationLevel.Function, "post", Route = "append")] HttpRequest req)
        {
            // Check that the data has been passed as JSON
            if (req.ContentType == null || !req.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
            {
                // Incorrect Content-Type, bad request
                return req.BadRequest("Content-Type must be application/json");
            }

            string subscriptionId = req.Headers[SubscriptionIdHeaderKey].ToString();
            if (string.IsNullOrEmpty(subscriptionId))
            {
                return req.BadRequest("Api-Subscription-Id header missing or invalid");
            }

            Activity.Current?.AddTag("SubscriptionId", subscriptionId);
            try
            {
                PwnedPasswordAppend[]? data = await JsonSerializer.DeserializeAsync<PwnedPasswordAppend[]>(req.Body);
                if (data != null)
                {
                    if (req.TryValidateEntries(data, out IActionResult? errorResponse))
                    {
                        // Now insert the data
                        string transactionId = await _tableStorage.InsertAppendData(data, subscriptionId);
                        return new OkObjectResult(new { transactionId });
                    }

                    return errorResponse;
                }

                return req.BadRequest("No content provided.");
            }
            catch (JsonException e)
            {
                // Error occurred trying to deserialize the JSON payload.
                _log.LogError(e, "Unable to parson JSON for subscription {SubscriptionId}", subscriptionId);
                return req.BadRequest($"Unable to parse JSON: {e.Message}");
            }
        }

        [FunctionName("ConfirmIngestion")]
        public async Task<IActionResult> ConfirmAppend([HttpTrigger(AuthorizationLevel.Function, "post", Route = "append/confirm")] HttpRequest req)
        {
            // Check that the data has been passed as JSON
            if (req.ContentType == null || !req.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
            {
                // Incorrect Content-Type, bad request
                return req.BadRequest("Content-Type must be application/json");
            }

            string subscriptionId = req.Headers[SubscriptionIdHeaderKey].ToString();
            if (string.IsNullOrEmpty(subscriptionId))
            {
                return req.BadRequest("Api-Subscription-Id header missing or invalid");
            }

            Activity.Current?.AddTag("SubscriptionId", subscriptionId);
            try
            {
                ConfirmAppendModel? data = await JsonSerializer.DeserializeAsync<ConfirmAppendModel>(req.Body).ConfigureAwait(false);
                if (data != null && !string.IsNullOrEmpty(data.TransactionId))
                {
                    Activity.Current?.AddTag("TransactionId", subscriptionId);
                    return await _tableStorage.ConfirmAppendDataAsync(subscriptionId, data.TransactionId, _queueStorage);
                }

                return req.BadRequest("No content provided.");
            }
            catch (JsonException e)
            {
                // Error occurred trying to deserialize the JSON payload.
                _log.LogError(e, "Unable to parson JSON");
                return req.BadRequest($"Unable to parse JSON: {e.Message}");
            }
        }

        [FunctionName("ProcessTransactionQueueItem")]
        public async Task ProcessTransactionItemForAppend([QueueTrigger("%TableNamespace%-transaction", Connection = "PwnedPasswordsConnectionString")] QueueTransactionEntry item)
        {
            Activity.Current?.AddTag("SubscriptionId", item.SubscriptionId).AddTag("TransactionId", item.TransactionId);
            await _tableStorage.ProcessTransactionAsync(item.SubscriptionId, item.TransactionId, _queueStorage).ConfigureAwait(false);
        }


        [FunctionName("ProcessAppendQueueItem")]
        public async Task ProcessQueueItemForAppend([QueueTrigger("%TableNamespace%-ingestion", Connection = "PwnedPasswordsConnectionString")] AppendQueueItem item)
        {
            // Let's set some activity tags and log scopes so we have event correlation in our logs!
            Activity.Current?.AddTag("SubscriptionId", item.SubscriptionId).AddTag("TransactionId", item.TransactionId);
            await _tableStorage.UpdateHashTable(item).ConfigureAwait(false);

            string prefix = item.SHA1Hash[..5];
            string suffix = item.SHA1Hash[5..];

            bool blobUpdated = false;
            while (!blobUpdated)
            {
                BlobStorageEntry? blobFile = await _blobStorage.GetHashesByPrefix(prefix).ConfigureAwait(false);
                if (blobFile != null)
                {
                    // Let's read the existing blob into a sorted dictionary so we can write it back in order!
                    SortedDictionary<string, int> hashes = await ParseHashFile(blobFile).ConfigureAwait(false);

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
                    blobUpdated = await _blobStorage.UpdateBlobFile(prefix, hashes, blobFile.ETag).ConfigureAwait(false);
                    if (blobUpdated)
                    {
                        _log.LogInformation("Subscription {SubscriptionId} successfully updated blob {HashPrefix} as part of transaction {TransactionId}!", item.SubscriptionId, prefix, item.TransactionId);
                    }
                    else
                    {
                        _log.LogWarning("Subscription {SubscriptionId} failed to updated blob {HashPrefix} as part of transaction {TransactionId}! Will retry!", item.SubscriptionId, prefix, item.TransactionId);
                    }
                }
                else
                {
                    _log.LogError("Subscription {SubscriptionId} is unable to find a hash file with prefix {prefix} as part of transaction {TransactionId}. Something is wrong as this shouldn't happen!", item.SubscriptionId, prefix, item.TransactionId);
                    return;
                }
            }
        }

        private static async Task<SortedDictionary<string, int>> ParseHashFile(BlobStorageEntry blobFile)
        {
            var hashes = new SortedDictionary<string, int>();
            using (blobFile.Stream)
            {
                using (var reader = new StreamReader(blobFile.Stream))
                {
                    while (!reader.EndOfStream)
                    {
                        string? hashLine = await reader.ReadLineAsync().ConfigureAwait(false);
                        // Let's make sure we can parse this as a proper hash!
                        if (!string.IsNullOrEmpty(hashLine) && hashLine.Length >= 37 && hashLine[35] == ':' && int.TryParse(hashLine[36..], out int currentPrevalence))
                        {
                            hashes.Add(hashLine[..35], currentPrevalence);
                        }
                    }
                }
            }

            return hashes;
        }

        #region Timer Functions

        /// <summary>
        /// Updates the contents of the Azure Storage Blobs from the Azure Storage Table data.
        /// This currently runs every day at 30 minutes past midnight.
        /// </summary>
        /// <param name="timer">Timer information</param>
        /// <param name="log">Logger</param>
        [FunctionName("UpdateCloudflareCache")]
        public async Task PurgeCloudflareCache(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            [TimerTrigger("0 30 0 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 30 0 * * *")]
#endif
            TimerInfo timer)
        {
            if (timer.ScheduleStatus == null)
            {
                _log.LogWarning("ScheduleStatus is null - this is required");
                return;
            }

            // Get a list of the partitions which have been modified
            string[]? modifiedPartitions = await _tableStorage.GetModifiedBlobs();

            if (modifiedPartitions.Length == 0)
            {
                return;
            }

            if (modifiedPartitions.Length > 0)
            {
                await _cloudflare.PurgeFile(modifiedPartitions).ConfigureAwait(false);
                _log.LogInformation($"Successfully purged Cloudflare Cache.");
            }
            else
            {
                _log.LogInformation($"Detected no purges needed for Cloudflare cache.");

            }
        }
        #endregion
    }
}
