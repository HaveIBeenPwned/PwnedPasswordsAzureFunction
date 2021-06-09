﻿using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Text;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Net.Http.Headers;
using System.IO;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly BlobStorage _blobStorage;

        private readonly TableStorage _tableStorage;

        private readonly StorageQueue _queue;

        private readonly Cloudflare _cloudflare;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="blobStorage">The Blob storage</param>
        public Range(BlobStorage blobStorage, TableStorage tableStorage, StorageQueue queue, Cloudflare cloudflare)
        {
            _blobStorage = blobStorage;
            _tableStorage = tableStorage;
            _queue = queue;
            _cloudflare = cloudflare;
        }

        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns></returns>
        [Function("Range-GET")]
        public async Task<HttpResponseData> RunAsync(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")]
            HttpRequestData req,
            string hashPrefix)
        {
            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return InvalidFormat("The hash prefix was not in a valid format", req);
            }

            var entry = await _blobStorage.GetByHashesByPrefix(hashPrefix.ToUpper());
            return entry == null ? NotFound(req) : File(req, entry);
        }

        private static HttpResponseData InvalidFormat(string error, HttpRequestData req)
        {
            var response = req.CreateResponse(HttpStatusCode.BadRequest);
            response.WriteString(error);
            return response;
        }

        private static HttpResponseData NotFound(HttpRequestData req)
        {
            var response = req.CreateResponse(HttpStatusCode.NotFound);
            response.WriteString("The hash prefix was not found");
            return response;
        }

        private static HttpResponseData File(HttpRequestData req, BlobStorageEntry entry)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            if (entry.LastModified.HasValue)
            {
                response.Headers.Add(HeaderNames.LastModified, entry.LastModified.Value.ToString("R"));
            }

            response.Body = entry.Stream;
            return response;
        }

        private static HttpResponseData Ok(string contents, HttpRequestData req)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.WriteString(contents);
            return response;
        }

        private static HttpResponseData ServerError(string contents, HttpRequestData req)
        {
            var response = req.CreateResponse(HttpStatusCode.InternalServerError);
            response.WriteString(contents);
            return response;
        }

        /// <summary>
        /// Handle a request to /range/append
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns>Response to the requesting client</returns>
        [Function("AppendPwnedPassword")]
        public async Task<HttpResponseData> AppendData(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "range/append")]
            HttpRequestData req,
            FunctionContext context)
        {
            var log = context.GetLogger("AppendPwnedPassword");
            // Check that the data has been passed as JSON
            if (req.Headers.TryGetValues(HeaderNames.ContentType, out var contentType) && contentType.First().ToLower() != "application/json")
            {
                // Incorrect Content-Type, bad request
                return InvalidFormat("Content-Type must be application/json", req);
            }

            try
            {
                var validateSw = Stopwatch.StartNew();

                // Get JSON POST request body
                var stream = new StreamReader(req.Body);
                string content = await stream.ReadToEndAsync();
                PwnedPasswordAppend[] data = JsonConvert.DeserializeObject<PwnedPasswordAppend[]>(content);

                // First validate the data
                if (data == null)
                {
                    // Json wasn't parsed from POST body, bad request
                    return InvalidFormat("Missing JSON body", req);
                }
                
                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] == null)
                    {
                        // Null item in the array, bad request
                        return InvalidFormat("Null PwnedPassword append entity at " + i, req);
                    }

                    if (string.IsNullOrEmpty(data[i].SHA1Hash))
                    {
                        // Empty SHA-1 hash, bad request
                        return InvalidFormat("Missing SHA-1 hash for item at index " + i, req);
                    }
                    if (!data[i].SHA1Hash.IsStringSHA1Hash())
                    {
                        // Invalid SHA-1 hash, bad request
                        return InvalidFormat("The SHA-1 hash was not in a valid format for item at index " + i, req);
                    }

                    if (string.IsNullOrEmpty(data[i].NTLMHash))
                    {
                        // Empty NTLM hash, bad request
                        return InvalidFormat("Missing NTLM hash for item at index " + i, req);
                    }
                    if (!data[i].NTLMHash.IsStringNTLMHash())
                    {
                        // Invalid NTLM hash, bad request
                        return InvalidFormat("The NTLM has was not in a valid format at index " + i, req);
                    }

                    if (data[i].Prevalence <= 0)
                    {
                        // Prevalence not set or invalid value, bad request
                        return InvalidFormat("Missing or invalid prevalence value for item at index " + i, req);
                    }
                }

                validateSw.Stop();
                log.LogInformation($"Validated {data.Length} items in {validateSw.ElapsedMilliseconds:n0}ms");

                var failedAttempts = new List<PwnedPasswordAppend>();

                string originIP = "";
                if (req.Headers.TryGetValues("CF-Connecting-IP", out var ip))
                {
                    originIP = ip.First();
                }
                else
                {
                    log.LogWarning("Request does not have a CF-Connecting-IP header, using empty string as client identifier");
                }

                var queueSw = Stopwatch.StartNew();

                // Now insert the data
                for (int i = 0; i < data.Length; i++)
                {
                    var contentID = $"{originIP}|{data[i]}".CreateSHA1Hash();
                    
                    if (!await _tableStorage.IsNotDuplicateRequest(contentID))
                    {
                        continue;
                    }

                    await _queue.PushPassword(data[i]);
                }

                queueSw.Stop();
                log.LogInformation("Added {items} items in {ElapsedMilliseconds}ms", data.Length, queueSw.ElapsedMilliseconds.ToString("n0"));

                if (failedAttempts.Count > 0)
                {
                    // We have some failed attempts, that means that some items were unable to be added, internal server error
                    StringBuilder errorMessage = new StringBuilder("Unable to add following entries to Pwned Passwords:\n");
                    foreach (var failedAttempt in failedAttempts)
                    {
                        errorMessage.Append($"{JsonConvert.SerializeObject(failedAttempt, Formatting.None)}\n");
                    }

                    return ServerError(errorMessage.ToString(), req);
                }


                return Ok(queueSw.ElapsedMilliseconds.ToString("n0") + "\n", req);
            }
            catch (JsonReaderException)
            {
                // Everything can be string, but Prevalence must be an int, so it can cause a JsonReader exception, Bad Request
                return InvalidFormat("Unable to parse JSON", req);
            }
            catch (JsonSerializationException)
            {
                // Invalid array passed, Bad Request
                return InvalidFormat("Unable to parse JSON", req);
            }
        }

        #region Timer Functions

        /// <summary>
        /// Updates the contents of the Azure Storage Blobs from the Azure Storage Table data.
        /// This currently runs every day at midnight
        /// </summary>
        /// <param name="timer">Timer information</param>
        /// <param name="log">Logger</param>
        //[Function("UpdateStorageBlobs")]
        public async Task UpdateStorageBlobs(
            [TimerTrigger("0 0 0 * * *")]
            TimerInfo timer,
            FunctionContext context)
        {
            var log = context.GetLogger("UpdateStorageBlobs");
            log.LogInformation($"Initiating scheduled Blob Storage update. Last run {timer.ScheduleStatus.Last.ToUniversalTime()}");

            var sw = Stopwatch.StartNew();

            // Get a list of the partitions which have been modified
            var modifiedPartitions = await _tableStorage.GetModifiedPartitions(timer.ScheduleStatus.Last);

            if (modifiedPartitions.Length == 0)
            {
                sw.Stop();
                log.LogInformation($"Detected no changes needed for Blob Storage in {sw.ElapsedMilliseconds:n0}ms");
                return;
            }

            var updateSw = Stopwatch.StartNew();

            for (int i = 0; i < modifiedPartitions.Length; i++)
            {
                var hashPrefixFileContents = _tableStorage.GetByHashesByPrefix(modifiedPartitions[i], out _);

                // Write the updated values to the Blob Storage
                await _blobStorage.UpdateBlobFile(modifiedPartitions[i], hashPrefixFileContents);

                // Now that we've successfully updated the Blob Storage, remove the partition from the table
                await _tableStorage.RemoveModifiedPartitionFromTable(modifiedPartitions[i]);
            }
            updateSw.Stop();
            log.LogInformation($"Writing to Blob Storage took {sw.ElapsedMilliseconds:n0}ms");

            if (modifiedPartitions.Length > 0)
            {
                await _cloudflare.PurgeFile(modifiedPartitions);
            }

            sw.Stop();
            log.LogInformation($"Successfully updated Blob Storage in {sw.ElapsedMilliseconds:n0}ms");
        }

        //[Function("ClearIdempotencyCache")]
        public async Task ClearIdempotencyCache(
            [TimerTrigger("0 0 */1 * * *")]
            TimerInfo timer,
            FunctionContext context)
        {
            var log = context.GetLogger("ClearIdempotencyCache");
            await _tableStorage.RemoveOldDuplicateRequests();
            log.LogInformation($"Next cleanup will occur at {timer.ScheduleStatus.Next}");
        }

        #endregion

        [Function("ProcessAppendQueueItem")]
        public async Task ProcessQueueItemForAppend(
            [QueueTrigger("%PasswordIngestQueueName%", Connection = "PwnedPasswordsConnectionString")]
            PwnedPasswordAppend item,
            FunctionContext context
            )
        {
            var log = context.GetLogger("ProcessAppendQueueItem");
            var sw = Stopwatch.StartNew();
            await _tableStorage.UpdateHash(item);
            sw.Stop();
            log.LogInformation($"Total update completed in {sw.ElapsedMilliseconds:n0}ms");
        }
    }
}
