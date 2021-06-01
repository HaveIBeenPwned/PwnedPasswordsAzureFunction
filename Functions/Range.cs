using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
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

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="configuration">Configuration instance</param>
        public Range(IConfiguration configuration)
        {
            this._configuration = configuration;
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
    }
}
