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

            string subscriptionId = req.Headers["Api-Subscription-Id"].ToString();
            if (string.IsNullOrEmpty(subscriptionId))
            {
                return req.BadRequest("Api-Subscription-Id header missing or invalid");
            }

            Activity.Current?.AddTag("SubscriptionId", subscriptionId);
            using (_log.BeginScope("{SubscriptionId}", subscriptionId))
            {
                try
                {
                    var validateSw = Stopwatch.StartNew();
                    PwnedPasswordAppend[]? data = await JsonSerializer.DeserializeAsync<PwnedPasswordAppend[]>(req.Body);
                    if (data != null)
                    {
                        if (req.TryValidateEntries(data, out IActionResult? errorResponse))
                        {
                            validateSw.Stop();
                            _log.LogInformation($"Validated {data.Length} items in {validateSw.ElapsedMilliseconds:n0}ms");

                            // Now insert the data
                            var queueSw = Stopwatch.StartNew();
                            string transactionId = await _tableStorage.InsertAppendData(data, subscriptionId);
                            queueSw.Stop();
                            _log.LogInformation("Added {items} items in {ElapsedMilliseconds}ms", data.Length, queueSw.ElapsedMilliseconds.ToString("n0"));

                            return new OkObjectResult(new { transactionId });
                        }

                        return errorResponse;
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

            string subscriptionId = req.Headers["Api-Subscription-Id"].ToString();
            if (string.IsNullOrEmpty(subscriptionId))
            {
                return req.BadRequest("Api-Subscription-Id header missing or invalid");
            }

            Activity.Current?.AddTag("SubscriptionId", subscriptionId);
            using (_log.BeginScope("{SubscriptionId}", subscriptionId))
            {
                try
                {
                    ConfirmAppendModel? data = await JsonSerializer.DeserializeAsync<ConfirmAppendModel>(req.Body);
                    if (data != null && !string.IsNullOrEmpty(data.TransactionId))
                    {
                        IActionResult result = await _tableStorage.ConfirmAppendDataAsync(subscriptionId, data.TransactionId, _queueStorage);
                        return result;
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
        }

        [FunctionName("ProcessAppendQueueItem")]
        public async Task ProcessQueueItemForAppend([QueueTrigger("%TableNamespace%-ingestion", Connection = "PwnedPasswordsConnectionString")]AppendQueueItem item)
        {
            // Let's set some activity tags and log scopes so we have event correlation in our logs!
            Activity.Current?.AddTag("SubscriptionId", item.SubscriptionId).AddTag("TransactionId", item.TransactionId);
            using (var scope = _log.BeginScope("{SubscriptionId:TransactionId}", item.SubscriptionId, item.TransactionId))
            {
                await _tableStorage.UpdateHashTable(item);

                string prefix = item.SHA1Hash[..5];
                string suffix = item.SHA1Hash[5..];

                bool blobUpdated = false;
                while (!blobUpdated)
                {
                    BlobStorageEntry? blobFile = await _blobStorage.GetHashesByPrefix(prefix);
                    if (blobFile != null)
                    {
                        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
                        SortedDictionary<string, int> hashes = await ParseHashFile(blobFile);

                        // We now have a sorted dictionary with the hashes for this prefix.
                        // Let's add or update the suffix with the prevalence count.
                        if (hashes.ContainsKey(suffix))
                        {
                            hashes[suffix] = hashes[suffix] + item.Prevalence;
                        }
                        else
                        {
                            hashes.Add(suffix, item.Prevalence);
                        }

                        // Now let's try to update the current blob with the new prevalence count!
                        blobUpdated = await _blobStorage.UpdateBlobFile(prefix, hashes, blobFile.ETag);
                    }
                    else
                    {
                        _log.LogError($"Unable to find a hash file with prefix {prefix}. Something is wrong!");
                        return;
                    }
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
                        string? hashLine = await reader.ReadLineAsync();
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
        //[Function("UpdateCloudflareCache")]
        public async Task PurgeCloudflareCache(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            //[TimerTrigger("0 30 0 * * *", RunOnStartup = true)]
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

            _log.LogInformation($"Initiating scheduled Blob Storage update. Last run {timer.ScheduleStatus.Last.ToUniversalTime()}");

            var sw = Stopwatch.StartNew();

            // Get a list of the partitions which have been modified
            string[]? modifiedPartitions = await _tableStorage.GetModifiedPartitions(timer.ScheduleStatus.Last);

            if (modifiedPartitions.Length == 0)
            {
                sw.Stop();
                _log.LogInformation($"Detected no purges needed for Cloudflare cache in {sw.ElapsedMilliseconds:n0}ms");
                return;
            }

            var updateSw = Stopwatch.StartNew();

            for (int i = 0; i < modifiedPartitions.Length; i++)
            {
                // Now that we've successfully updated the Blob Storage, remove the partition from the table
                await _tableStorage.RemoveModifiedPartitionFromTable(modifiedPartitions[i]);
            }
            updateSw.Stop();
            _log.LogInformation($"Removing existing modified partitions from Table Storage took {sw.ElapsedMilliseconds:n0}ms");

            if (modifiedPartitions.Length > 0)
            {
                await _cloudflare.PurgeFile(modifiedPartitions);
            }

            sw.Stop();
            _log.LogInformation($"Successfully updated Cloudflare Cache in {sw.ElapsedMilliseconds:n0}ms");
        }

        //[Function("ClearIdempotencyCache")]
        public async Task ClearIdempotencyCache(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            //[TimerTrigger("0 0 */1 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 */1 * * *")]
#endif
            TimerInfo timer)
        {
            await _tableStorage.RemoveOldDuplicateRequests();
            if (timer.ScheduleStatus != null)
            {
                _log.LogInformation($"Next idempotency cache cleanup will occur at {timer.ScheduleStatus.Next}");
            }
        }

        #endregion
    }
}
