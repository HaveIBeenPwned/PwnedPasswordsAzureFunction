using System.Net;
using System.Threading.Tasks;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Net.Http.Headers;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly BlobStorage _blobStorage;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="blobStorage">The Blob storage</param>
        public Range(BlobStorage blobStorage)
        {
            _blobStorage = blobStorage;
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
                return InvalidFormat(req);
            }

            var entry = await _blobStorage.GetByHashesByPrefix(hashPrefix.ToUpper());
            return entry == null ? NotFound(req) : File(req, entry);
        }

        private static HttpResponseData InvalidFormat(HttpRequestData req)
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
            response.Headers.Add(HeaderNames.LastModified, entry.LastModified.ToString("R"));
            response.Body = entry.Stream;
            return response;
        }
    }
}
