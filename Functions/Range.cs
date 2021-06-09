using System;
using System.Net;
using System.Threading.Tasks;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly IStorageService _blobStorage;
        private readonly ILogger<Range> _log;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="blobStorage">The Blob storage</param>
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
        public async Task<HttpResponseData> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestData req, string hashPrefix)
        {
            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return BadRequest(req);
            }

            try
            {
                var entry = await _blobStorage.GetHashesByPrefix(hashPrefix.ToUpper());
                return entry == null ? NotFound(req) : File(req, entry);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Something went wrong.");
                return InternalServerError(req);
            }
        }

        private static HttpResponseData BadRequest(HttpRequestData req)
        {
            var response = req.CreateResponse(HttpStatusCode.BadRequest);
            response.WriteString("The hash prefix was not in a valid format");
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

        private static HttpResponseData InternalServerError(HttpRequestData req)
        {
            var response = req.CreateResponse(HttpStatusCode.InternalServerError);
            response.WriteString("Something went wrong.");
            return response;
        }
    }
}
