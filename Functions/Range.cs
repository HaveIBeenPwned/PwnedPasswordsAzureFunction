using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly IStorageService _blobStorage;
        private readonly ILogger<Range> _log;

        private readonly TableStorage _tableStorage;

        private readonly StorageQueue _queue;

        private readonly Cloudflare _cloudflare;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="blobStorage">The Blob storage</param>
        public Range(IStorageService blobStorage, TableStorage tableStorage, StorageQueue queue, Cloudflare cloudflare, ILogger<Range> log)
        {
            _blobStorage = blobStorage;
            _tableStorage = tableStorage;
            _queue = queue;
            _cloudflare = cloudflare;
            _log = log;
        }

        // TODO: Remove
        public Range(IStorageService blobStorage, ILogger<Range> log)
        {
            _blobStorage = blobStorage;
            _log = log;
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
            TelemetryClient? telemetryClient = req.GetInstanceService<TelemetryClient>();
            using (IOperationHolder<RequestTelemetry>? requestTelemetry = telemetryClient?.StartOperation<RequestTelemetry>(req.FunctionContext.FunctionDefinition.Name))
            {
                if (requestTelemetry is not null)
                {
                    Activity.Current?.SetParentId(req.FunctionContext.TraceContext.TraceParent);
                    requestTelemetry.Telemetry.Context.Operation.ParentId = Activity.Current?.ParentId;
                    requestTelemetry.Telemetry.Url = req.Url;
                    req.FunctionContext.Features.Set(requestTelemetry.Telemetry);
                }

                if (!hashPrefix.IsHexStringOfLength(5))
                {
                    return BadRequest("The hash format was not in a valid format", req);
                }

                try
                {
                    BlobStorageEntry? entry = await _blobStorage.GetHashesByPrefix(hashPrefix.ToUpper());
                    return entry == null ? NotFound(req) : File(req, entry);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Something went wrong.");
                    return InternalServerError(req);
                }
            }
        }

        private static HttpResponseData BadRequest(string error, HttpRequestData req)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.BadRequest);
            response.WriteString(error);
            RequestTelemetry? telemetry = req.GetFeatureService<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = false;
                telemetry.ResponseCode = "400";
            }

            return response;
        }

        private static HttpResponseData NotFound(HttpRequestData req)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.NotFound);
            response.WriteString("The hash prefix was not found");
            RequestTelemetry? telemetry = req.GetFeatureService<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = false;
                telemetry.ResponseCode = "404";
            }

            return response;
        }

        private static HttpResponseData File(HttpRequestData req, BlobStorageEntry entry)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add(HeaderNames.LastModified, entry.LastModified.ToString("R"));
            response.Body = entry.Stream;
            RequestTelemetry? telemetry = req.GetFeatureService<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = true;
                telemetry.ResponseCode = "200";
            }

            return response;
        }

        private static HttpResponseData InternalServerError(HttpRequestData req)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.InternalServerError);
            response.WriteString("Something went wrong.");
            RequestTelemetry? telemetry = req.GetFeatureService<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = false;
                telemetry.ResponseCode = "500";
            }

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
            // Check that the data has been passed as JSON
            if (req.Headers.TryGetValues(HeaderNames.ContentType, out var contentType) && contentType.First().ToLower() != "application/json")
            {
                // Incorrect Content-Type, bad request
                return BadRequest("Content-Type must be application/json", req);
            }

            try
            {
                var validateSw = Stopwatch.StartNew();

                // Get JSON POST request body
                var stream = new StreamReader(req.Body);
                string content = await stream.ReadToEndAsync();
                PwnedPasswordAppend[]? data = JsonConvert.DeserializeObject<PwnedPasswordAppend[]>(content);

                // First validate the data
                if (data == null)
                {
                    // Json wasn't parsed from POST body, bad request
                    return BadRequest("Missing JSON body", req);
                }
                
                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] == null)
                    {
                        // Null item in the array, bad request
                        return BadRequest("Null PwnedPassword append entity at " + i, req);
                    }

                    if (string.IsNullOrEmpty(data[i].SHA1Hash))
                    {
                        // Empty SHA-1 hash, bad request
                        return BadRequest("Missing SHA-1 hash for item at index " + i, req);
                    }
                    if (!data[i].SHA1Hash.IsStringSHA1Hash())
                    {
                        // Invalid SHA-1 hash, bad request
                        return BadRequest("The SHA-1 hash was not in a valid format for item at index " + i, req);
                    }

                    if (string.IsNullOrEmpty(data[i].NTLMHash))
                    {
                        // Empty NTLM hash, bad request
                        return BadRequest("Missing NTLM hash for item at index " + i, req);
                    }
                    if (!data[i].NTLMHash.IsStringNTLMHash())
                    {
                        // Invalid NTLM hash, bad request
                        return BadRequest("The NTLM has was not in a valid format at index " + i, req);
                    }

                    if (data[i].Prevalence <= 0)
                    {
                        // Prevalence not set or invalid value, bad request
                        return BadRequest("Missing or invalid prevalence value for item at index " + i, req);
                    }
                }

                validateSw.Stop();
                _log.LogInformation($"Validated {data.Length} items in {validateSw.ElapsedMilliseconds:n0}ms");

                var failedAttempts = new List<PwnedPasswordAppend>();

                string originIP = "";
                if (req.Headers.TryGetValues("CF-Connecting-IP", out var ip))
                {
                    originIP = ip.First();
                }
                else
                {
                    _log.LogWarning("Request does not have a CF-Connecting-IP header, using empty string as client identifier");
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
                _log.LogInformation("Added {items} items in {ElapsedMilliseconds}ms", data.Length, queueSw.ElapsedMilliseconds.ToString("n0"));

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
                return BadRequest("Unable to parse JSON", req);
            }
            catch (JsonSerializationException)
            {
                // Invalid array passed, Bad Request
                return BadRequest("Unable to parse JSON", req);
            }
        }

        #region Timer Functions

        /// <summary>
        /// Updates the contents of the Azure Storage Blobs from the Azure Storage Table data.
        /// This currently runs every day at midnight
        /// </summary>
        /// <param name="timer">Timer information</param>
        /// <param name="log">Logger</param>
        //[Function("UpdateCloudflareCache")]
        public async Task UpdateStorageBlobs(
#if DEBUG
            // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
            // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
            [TimerTrigger("0 0 0 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 0 * * *")]
#endif
            TimerInfo timer,
            FunctionContext context)
        {
            if (timer.ScheduleStatus == null)
            {
                _log.LogWarning("ScheduleStatus is null - this is required");
                return;
            }

            _log.LogInformation($"Initiating scheduled Blob Storage update. Last run {timer.ScheduleStatus.Last.ToUniversalTime()}");

            var sw = Stopwatch.StartNew();

            // Get a list of the partitions which have been modified
            var modifiedPartitions = await _tableStorage.GetModifiedPartitions(timer.ScheduleStatus.Last);

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
            [TimerTrigger("0 0 */1 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 0 */1 * * *")]
#endif
            TimerInfo timer,
            FunctionContext context)
        {
            await _tableStorage.RemoveOldDuplicateRequests();
            if (timer.ScheduleStatus != null)
            {
                _log.LogInformation($"Next idempotency cache cleanup will occur at {timer.ScheduleStatus.Next}");
            }
        }

        #endregion

        [Function("ProcessAppendQueueItem")]
        public async Task ProcessQueueItemForAppend(
            [QueueTrigger("%PasswordIngestQueueName%", Connection = "PwnedPasswordsConnectionString")]
            PwnedPasswordAppend item,
            FunctionContext context
            )
        {
            var sw = Stopwatch.StartNew();
            await _tableStorage.UpdateHash(item);

            string? hashPrefixFileContents = _tableStorage.GetByHashesByPrefix(item.PartitionKey, out _);

            // Write the updated values to the Blob Storage
            await _blobStorage.UpdateBlobFile(item.PartitionKey, hashPrefixFileContents);

            sw.Stop();
            _log.LogInformation($"Total update completed in {sw.ElapsedMilliseconds:n0}ms");
        }
    }
}
