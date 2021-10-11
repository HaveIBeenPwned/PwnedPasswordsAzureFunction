using System;
using System.Diagnostics;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace HaveIBeenPwned.PwnedPasswords.Functions
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
        [FunctionName("Range-GET")]
        public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequest req, string hashPrefix)
        {
            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return req.BadRequest("The hash format was not in a valid format");
            }

            try
            {
                BlobStorageEntry? entry = await _blobStorage.GetHashesByPrefix(hashPrefix.ToUpper());
                return entry == null ? req.NotFound() : req.File(entry);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Something went wrong.");
                return req.InternalServerError();
            }
        }
    }
}
