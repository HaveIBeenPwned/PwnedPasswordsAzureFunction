using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger _log;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="configuration">Configuration instance</param>
        public Range(IConfiguration configuration, ILoggerFactory logFactory)
        {
            _configuration = configuration;
            _log = logFactory.CreateLogger("Range");
        }
        
        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns></returns>
        [Function("Range-GET")]
        public Task<HttpResponseData> RunAsync(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestData req,
            string hashPrefix)
        {
            return GetData(req, hashPrefix);
        }

        /// <summary>
        /// Get the data for the request
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns>Http Response message to return to the client</returns>
        private async Task<HttpResponseData> GetData(
            HttpRequestData req,
            string hashPrefix)
        {
            if (string.IsNullOrEmpty(hashPrefix))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing hash prefix");
            }

            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The hash prefix was not in a valid format");
            }

            var storage = new BlobStorage(_configuration, _log);
            var entry = await storage.GetByHashesByPrefix(hashPrefix.ToUpper());
            if (entry == null)
            {
                return PwnedResponse.CreateResponse(req, HttpStatusCode.NotFound, "The hash prefix was not found");
            }
            
            var response = PwnedResponse.CreateResponse(req, HttpStatusCode.OK, null, entry.Stream, entry.LastModified);
            return response;
        }
    }
}
