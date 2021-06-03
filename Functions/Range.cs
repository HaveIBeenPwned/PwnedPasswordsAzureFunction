using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Azure.Storage.Queue;
using System.Text;
using System;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly IConfiguration _configuration;

        private static int QueueCount = 0;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="configuration">Configuration instance</param>
        public Range(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        
        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns></returns>
        [FunctionName("Range-GET")]
        public Task<HttpResponseMessage> RunAsync(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestMessage req,
            string hashPrefix,
            ILogger log)
        {
            return GetData(req, hashPrefix, log);
        }

        /// <summary>
        /// Get the data for the request
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns>Http Response message to return to the client</returns>
        private async Task<HttpResponseMessage> GetData(
            HttpRequestMessage req,
            string hashPrefix,
            ILogger log)
        {
            if (string.IsNullOrEmpty(hashPrefix))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing hash prefix");
            }

            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The hash prefix was not in a valid format");
            }

            var storage = new BlobStorage(_configuration, log);
            var entry = await storage.GetByHashesByPrefix(hashPrefix.ToUpper());
            if (entry == null)
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.NotFound, "The hash prefix was not found");
            }
            
            var response = PwnedResponse.CreateResponse(req, HttpStatusCode.OK, null, entry.Stream, entry.LastModified);
            return response;
        }

        /// <summary>
        /// Handle a request to /range/append
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns>Response to the requesting client</returns>
        [FunctionName("AppendPwnedPassword")]
        public async Task<HttpResponseMessage> AppendData(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "range/append")]
            HttpRequestMessage req,
            ILogger log)
        {
            // Check that the data has been passed as JSON
            if (req.Content.Headers.ContentType.MediaType.ToLower() != "application/json")
            {
                // Incorrect Content-Type, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Content-Type must be application/json");
            }

            try
            {
                var validateSw = Stopwatch.StartNew();

                // Get JSON POST request body
                PwnedPasswordAppend[] data = await req.Content.ReadAsAsync<PwnedPasswordAppend[]>();

                // First validate the data
                if (data == null)
                {
                    // Json wasn't parsed from POST body, bad request
                    return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing JSON body");
                }
                
                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] == null)
                    {
                        // Null item in the array, bad request
                        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Null PwnedPassword append entity at " + i);
                    }

                    if (string.IsNullOrEmpty(data[i].SHA1Hash))
                    {
                        // Empty SHA-1 hash, bad request
                        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing SHA-1 hash for item at index " + i);
                    }
                    if (!data[i].SHA1Hash.IsStringSHA1Hash())
                    {
                        // Invalid SHA-1 hash, bad request
                        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The SHA-1 hash was not in a valid format for item at index " + i);
                    }

                    if (string.IsNullOrEmpty(data[i].NTLMHash))
                    {
                        // Empty NTLM hash, bad request
                        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing NTLM hash for item at index " + (i + 1));
                    }
                    if (!data[i].NTLMHash.IsStringNTLMHash())
                    {
                        // Invalid NTLM hash, bad request
                        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The NTLM hash was not in a valid format for item at index " + i);
                    }

                    if (data[i].Prevalence <= 0)
                    {
                        // Prevalence not set or invalid value, bad request
                        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing or invalid prevalence value for item at index " + i);
                    }
                }

                validateSw.Stop();
                log.LogInformation($"Validated {data.Length} items in {validateSw.ElapsedMilliseconds:n0}ms");

                var storage = new TableStorage(_configuration, log);

                var failedAttempts = new List<PwnedPasswordAppend>();

                string originIP = "";
                if (req.Headers.TryGetValues("CF-Connecting-IP", out var ip))
                {
                    originIP = ip.FirstOrDefault();
                }
                else
                {
                    log.LogWarning("Request does not have a CF-Connecting-IP header, using empty string as client identifier");
                }

                var queue = new StorageQueue(_configuration, log);

                var queueSw = Stopwatch.StartNew();

                // Now insert the data
                for (int i = 0; i < data.Length; i++)
                {
                    var contentID = $"{originIP}|{data[i]}".CreateSHA1Hash();
                    
                    if (!await storage.IsNotDuplicateRequest(contentID))
                    {
                        continue;
                    }

                    await queue.PushPassword(data[i]);
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
                    return PwnedResponse.CreateResponse(req, HttpStatusCode.InternalServerError, errorMessage.ToString());
                }

                return PwnedResponse.CreateResponse(req, HttpStatusCode.OK, queueSw.ElapsedMilliseconds.ToString("n0") + "\n");
            }
            catch (JsonReaderException)
            {
                // Everything can be string, but Prevalence must be an int, so it can cause a JsonReader exception, Bad Request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Unable to parse JSON");
            }
            catch (JsonSerializationException)
            {
                // Invalid array passed, Bad Request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Unable to parse JSON");
            }
        }

        #region Timer Functions

        /// <summary>
        /// Updates the contents of the Azure Storage Blobs from the Azure Storage Table data.
        /// This currently runs every day at midnight
        /// </summary>
        /// <param name="timer">Timer information</param>
        /// <param name="log">Logger</param>
        [FunctionName("UpdateStorageBlobs")]
        public async Task UpdateStorageBlobs(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            [TimerTrigger("0 0 0 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 0 * * *")]
#endif
            TimerInfo timer,
            ILogger log)
        {
            log.LogInformation($"Initiating scheduled Blob Storage update. Last run {timer.ScheduleStatus.Last.ToUniversalTime()}");

            var blobStorage = new BlobStorage(_configuration, log);
            var tableStorage = new TableStorage(_configuration, log);

            var sw = Stopwatch.StartNew();

            // Get a list of the partitions which have been modified
            var modifiedPartitions = await tableStorage.GetModifiedPartitions(timer.ScheduleStatus.Last);

            if (modifiedPartitions.Length == 0)
            {
                sw.Stop();
                log.LogInformation($"Detected no changes needed for Blob Storage in {sw.ElapsedMilliseconds:n0}ms");
                return;
            }

            var updateSw = Stopwatch.StartNew();

            for (int i = 0; i < modifiedPartitions.Length; i++)
            {
                var hashPrefixFileContents = tableStorage.GetByHashesByPrefix(modifiedPartitions[i], out _);

                // Write the updated values to the Blob Storage
                await blobStorage.UpdateBlobFile(modifiedPartitions[i], hashPrefixFileContents);

                // Now that we've successfully updated the Blob Storage, remove the partition from the table
                await tableStorage.RemoveModifiedPartitionFromTable(modifiedPartitions[i]);
            }
            updateSw.Stop();
            log.LogInformation($"Writing to Blob Storage took {sw.ElapsedMilliseconds:n0}ms");

            if (modifiedPartitions.Length > 0)
            {
                var cloudflare = new Cloudflare(_configuration, log);

                await cloudflare.PurgeFile(modifiedPartitions);
            }

            sw.Stop();
            log.LogInformation($"Successfully updated Blob Storage in {sw.ElapsedMilliseconds:n0}ms");
        }

        [FunctionName("ClearIdempotencyCache")]
        public async Task ClearIdempotencyCache(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            [TimerTrigger("0 0 */1 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 */1 * * *")]
#endif
            TimerInfo timer,
            ILogger log)
        {
            var tableStorage = new TableStorage(_configuration, log);
            await tableStorage.RemoveOldDuplicateRequests();
            log.LogInformation($"Next cleanup will occur at {timer.ScheduleStatus.Next}");
        }

        #endregion

        [FunctionName("ProcessAppendQueueItem")]
        public async Task ProcessQueueItemForAppend(
            [QueueTrigger("%PasswordIngestQueueName%", Connection = "PwnedPasswordsConnectionString")]
            CloudQueueMessage item,
            ILogger log
            )
        {
            var sw = Stopwatch.StartNew();
            var storage = new TableStorage(_configuration, log);
            var appendItem = JsonConvert.DeserializeObject<PwnedPasswordAppend>(item.AsString);
            await storage.UpdateHash(appendItem);
            sw.Stop();
            log.LogInformation($"Total update completed in {sw.ElapsedMilliseconds:n0}ms");
        }
    }
}
