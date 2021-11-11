using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
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
        private readonly ILogger<Range> _log;
        private readonly IFileStorage _fileStorage;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="fileStorage">The file storage</param>
        public Range(ILogger<Range> log, IFileStorage fileStorage)
        {
            _log = log;
            _fileStorage = fileStorage;
        }

        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns></returns>
        [FunctionName("Range-GET")]
        public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequest req, string hashPrefix, CancellationToken cancellationToken = default)
        {
            if (!hashPrefix.IsHexStringOfLength(5))
            {
                return req.BadRequest("The hash format was not in a valid format");
            }

            try
            {
                PwnedPasswordsFile entry = await _fileStorage.GetHashFileAsync(hashPrefix.ToUpper(), cancellationToken);
                return new FileStreamResult(entry.Stream, "text/plain") { LastModified = entry.LastModified };
            }
            catch (FileNotFoundException)
            {
                return req.NotFound();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Something went wrong.");
                return req.InternalServerError();
            }
        }
    }
}
