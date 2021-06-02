using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Newtonsoft.Json;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public static class Range
    {
        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns></returns>
        [FunctionName("Range-GET")]
        public static HttpResponseMessage RunRoute([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestMessage req, string hashPrefix, TraceWriter log)
        {
            return GetData(req, hashPrefix, log);
        }

        /// <summary>
        /// Get the data for the request
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns>Http Response message to return to the client</returns>
        private static HttpResponseMessage GetData(HttpRequestMessage req, string hashPrefix, TraceWriter log)
        {
            if (string.IsNullOrEmpty(hashPrefix))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing hash prefix");
            }

            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The hash prefix was not in a valid format");
            }

            var storage = new BlobStorage(log);
            var stream = storage.GetByHashesByPrefix(hashPrefix.ToUpper(), out var lastModified);
            var response = PwnedResponse.CreateResponse(req, HttpStatusCode.OK, null, stream, lastModified);
            return response;
        }

        /// <summary>
        /// Handle a request to /range/append
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="log">Trace writer to use to write to the log</param>
        /// <returns>Response to the requesting client</returns>
        [FunctionName("AppendPwnedPassword")]
        public static async Task<HttpResponseMessage> AppendData([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "range/append")] HttpRequestMessage req, TraceWriter log)
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
                log.Info($"Validated {data.Length} items in {validateSw.ElapsedMilliseconds:n0}ms");

                var storage = new TableStorage(log);

                var failedAttempts = new List<PwnedPasswordAppend>();

                string originIP = "";
                if (req.Headers.TryGetValues("CF-Connecting-IP", out var ip))
                {
                    originIP = ip.FirstOrDefault();
                }
                else
                {
                    log.Warning("Request does not have a CF-Connecting-IP header, using empty string as client identifier");
                }

                // Now insert the data
                for (int i = 0; i < data.Length; i++)
                {
                    var contentID = $"{originIP}|{data[i]}".CreateSHA1Hash();
                    var newEntry = await storage.UpdateHash(data[i], contentID);

                    switch (newEntry)
                    {
                        case EUpdateHashResult.DuplicateRequest:
                            log.Info("Client made duplicate request");
                            break;
                        case EUpdateHashResult.Error:
                            failedAttempts.Add(data[i]);
                            break;
                    }
                }

                if (failedAttempts.Count > 0)
                {
                    // We have some failed attempts, that means that some items were unable to be added, internal server error
                    var errorMessage = "Unable to add following entries to Pwned Passwords:\n";
                    foreach (var failedAttempt in failedAttempts)
                    {
                        errorMessage += $"{JsonConvert.SerializeObject(failedAttempt, Formatting.None)}\n";
                    }
                    return PwnedResponse.CreateResponse(req, HttpStatusCode.InternalServerError, errorMessage);
                }

                return PwnedResponse.CreateResponse(req, HttpStatusCode.OK, "");
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

        /// <summary>
        /// Updates the contents of the Azure Storage Blobs from the Azure Storage Table data.
        /// This currently runs every day at midnight
        /// </summary>
        /// <param name="timer">Timer information</param>
        /// <param name="log">Logger</param>
        [FunctionName("UpdateStorageBlobs")]
        public static async Task UpdateStorageBlobs(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            [TimerTrigger("0 0 0 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 0 * * *")]
#endif
        TimerInfo timer, TraceWriter log)
        {
            log.Info($"Initiating scheduled Blob Storage update. Last run {timer.ScheduleStatus.Last.ToUniversalTime()}");

            var blobStorage = new BlobStorage(log);
            var tableStorage = new TableStorage(log);

            var sw = Stopwatch.StartNew();

            // Get a list of the partitions which have been modified
            var modifiedPartitions = await tableStorage.GetModifiedPartitions(timer.ScheduleStatus.Last);

            if (modifiedPartitions.Length == 0)
            {
                sw.Stop();
                log.Info($"Detected no changes needed for Blob Storage in {sw.ElapsedMilliseconds:n0}ms");
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
            log.Info($"Writing to Blob Storage took {sw.ElapsedMilliseconds:n0}ms");

            if (modifiedPartitions.Length > 0)
            {
                var cloudflare = new Cloudflare(log);

                await cloudflare.PurgeFile(modifiedPartitions);
            }

            sw.Stop();
            log.Info($"Successfully updated Blob Storage in {sw.ElapsedMilliseconds:n0}ms");
        }

        [FunctionName("ClearIdempotencyCache")]
        public static async Task ClearIdempotencyCache(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            [TimerTrigger("0 0 */1 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 */1 * * *")]
#endif
        TimerInfo timer, TraceWriter log)
        {
            var tableStorage = new TableStorage(log);
            await tableStorage.RemoveOldDuplicateRequests();
            log.Info($"Next cleanup will occur at {timer.ScheduleStatus.Next}");
        }
    }
}
