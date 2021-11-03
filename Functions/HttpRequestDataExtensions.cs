using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace HaveIBeenPwned.PwnedPasswords
{
    internal static class HttpRequestDataExtensions
    {
        /// <summary>
        /// Returns a <see cref="HttpStatusCode.BadRequest"/> response with the specified error message.
        /// </summary>
        /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
        /// <param name="error">The error message to set as the response content.</param>
        /// <returns>The <see cref="HttpResponseData"/> response indicating a <see cref="HttpStatusCode.BadRequest"/> status code with the provided error message.</returns>
        internal static IActionResult BadRequest(this HttpRequest req, string error) => req.PlainTextResult(StatusCodes.Status400BadRequest, error);

        /// <summary>
        /// Returns a <see cref="HttpStatusCode.NotFound"/> response.
        /// </summary>
        /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
        /// <returns>A <see cref="HttpResponseData"/> response indicating that the resource was not found.</returns>
        internal static IActionResult NotFound(this HttpRequest req) => req.PlainTextResult(StatusCodes.Status404NotFound, "The hash prefix was not found");

        /// <summary>
        /// Returns a <see cref="HttpStatusCode.OK"/> response with the provided <see cref="PwnedPasswordsFile"/> file contents.
        /// </summary>
        /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
        /// <param name="entry">The <see cref="PwnedPasswordsFile"/> containing the file contents to return.</param>
        /// <returns>A <see cref="HttpResponseData"/> response containing the contents of the provided <see cref="PwnedPasswordsFile"/>.</returns>
        internal static IActionResult File(this HttpRequest req, PwnedPasswordsFile entry) => new FileStreamResult(entry.Stream, "text/plain") { LastModified = entry.LastModified };

        /// <summary>
        /// Returns a <see cref="HttpStatusCode.InternalServerError"/> response.
        /// </summary>
        /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
        /// <returns>A <see cref="HttpResponseData"/> response indicating an internal server error.</returns>
        internal static IActionResult InternalServerError(this HttpRequest req) => req.PlainTextResult(StatusCodes.Status500InternalServerError, "Something went wrong.");

        /// <summary>
        /// Returns a <see cref="HttpStatusCode.OK"/> response with the provided text response.
        /// </summary>
        /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
        /// <param name="contents">The text content to return.</param>
        /// <returns>A successful <see cref="HttpResponseData"/> response containing the provided text content.</returns>
        internal static IActionResult Ok(this HttpRequest req, string contents) => req.PlainTextResult(StatusCodes.Status200OK, contents);

        /// <summary>
        /// Returns a <see cref="HttpStatusCode.InternalServerError"/> response with the provided text response.
        /// </summary>
        /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
        /// <param name="contents">The text content to return.</param>
        /// <returns>A <see cref="HttpResponseData"/> response indicating an internal server error with the provided text content.</returns>
        internal static IActionResult InternalServerError(this HttpRequest req, string contents) => req.PlainTextResult(StatusCodes.Status500InternalServerError, contents);


        internal static async Task<(bool Success, IActionResult? Error)> TryValidateEntries(this HttpRequest req, IAsyncEnumerable<PwnedPasswordsIngestionValue?> entries)
        {
            // First validate the data
            if (entries == null)
            {
                // Json wasn't parsed from POST body, bad request
                return (false, req.BadRequest("Missing JSON body"));
            }

            int i = 0;
            await foreach (PwnedPasswordsIngestionValue? entry in entries)
            {
                i++;
                if (entry == null)
                {
                    // Null item in the array, bad request
                    return (false, req.BadRequest("Null PwnedPassword append entity at " + i));
                }

                if (string.IsNullOrEmpty(entry.SHA1Hash))
                {
                    // Empty SHA-1 hash, bad request
                    return (false, req.BadRequest("Missing SHA-1 hash for item at index " + i));
                }

                if (!entry.SHA1Hash.IsStringSHA1Hash())
                {
                    // Invalid SHA-1 hash, bad request
                    return (false, req.BadRequest("The SHA-1 hash was not in a valid format for item at index " + i));
                }

                if (string.IsNullOrEmpty(entry.NTLMHash))
                {
                    // Empty NTLM hash, bad request
                    return (false, req.BadRequest("Missing NTLM hash for item at index " + i));
                }

                if (!entry.NTLMHash.IsStringNTLMHash())
                {
                    // Invalid NTLM hash, bad request
                    return (false, req.BadRequest("The NTLM has was not in a valid format at index " + i));
                }

                if (entry.Prevalence <= 0)
                {
                    // Prevalence not set or invalid value, bad request
                    return (false, req.BadRequest("Missing or invalid prevalence value for item at index " + i));
                }
            }

            return (true, null);
        }

        private static IActionResult PlainTextResult(this HttpRequest _, int statusCode, string content) => new ContentResult { StatusCode = statusCode, Content = content, ContentType = "text/plain" };

    }
}
