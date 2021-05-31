using Functions.Services.HttpResponder;
using Functions.Services.Storage;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Functions
{
    public class Range
    {
        private const string MissingHashPrefixMessage = "Missing hash prefix";
        private const string InvalidHashPrefixMessage = "The hash prefix was not in a valid format";

        private readonly IHttpResponderService _responderService;
        private readonly IStorageService _storageService;
        private readonly ILogger<Range> _log;

        public Range(
            IHttpResponderService responderService,
            IStorageService storageService,
            ILogger<Range> log)
        {
            _responderService = responderService;
            _storageService = storageService;
            _log = log;
        }

        [Function("Range-GET")]
        public async Task<HttpResponseData> RunRoute(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestData req,
            string hashPrefix)
        {
            if (string.IsNullOrEmpty(hashPrefix))
            {
                _log.LogWarning(MissingHashPrefixMessage);
                return await _responderService.BadRequest(req, MissingHashPrefixMessage);
            }

            if (!IsValidPrefix(hashPrefix))
            {
                _log.LogWarning(InvalidHashPrefixMessage, hashPrefix);
                return await _responderService.BadRequest(req, InvalidHashPrefixMessage);
            }

            try
            {
                var hashFile = await _storageService.GetHashesByPrefix(hashPrefix.ToUpper());

                return await _responderService.Ok(req, hashFile.Content, hashFile.LastModified);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Something went wrong. Reason: {reason}", ex.Message);
                return await _responderService.InternalServerError(req, "Something went wrong.");
            }
        }

        protected virtual bool IsValidPrefix(string hashPrefix)
        {
            bool IsHex(char x) => (x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F');

            if (hashPrefix.Length != 5)
            {
                return false;
            }

            for (int i = 0; i < 5; i++)
            {
                if (!IsHex(hashPrefix[i]))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
