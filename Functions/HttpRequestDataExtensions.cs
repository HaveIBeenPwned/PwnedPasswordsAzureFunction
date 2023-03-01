using System.Net;

using Microsoft.Azure.Functions.Worker.Http;

namespace HaveIBeenPwned.PwnedPasswords;

internal static class HttpRequestDataExtensions
{
    /// <summary>
    /// Returns a <see cref="HttpStatusCode.BadRequest"/> response with the specified error message.
    /// </summary>
    /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
    /// <param name="error">The error message to set as the response content.</param>
    /// <returns>The <see cref="HttpResponseData"/> response indicating a <see cref="HttpStatusCode.BadRequest"/> status code with the provided error message.</returns>
    internal static HttpResponseData BadRequest(this HttpRequestData req, string error) => req.PlainTextResult(HttpStatusCode.BadRequest, error);

    /// <summary>
    /// Returns a <see cref="HttpStatusCode.NotFound"/> response.
    /// </summary>
    /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
    /// <returns>A <see cref="HttpResponseData"/> response indicating that the resource was not found.</returns>
    internal static HttpResponseData NotFound(this HttpRequestData req, string text) => req.PlainTextResult(HttpStatusCode.NotFound, text);

    /// <summary>
    /// Returns a <see cref="HttpStatusCode.InternalServerError"/> response.
    /// </summary>
    /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
    /// <returns>A <see cref="HttpResponseData"/> response indicating an internal server error.</returns>
    internal static HttpResponseData InternalServerError(this HttpRequestData req) => req.PlainTextResult(HttpStatusCode.InternalServerError, "Something went wrong.");

    /// <summary>
    /// Returns a <see cref="HttpStatusCode.OK"/> response with the provided text response.
    /// </summary>
    /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
    /// <param name="contents">The text content to return.</param>
    /// <returns>A successful <see cref="HttpResponseData"/> response containing the provided text content.</returns>
    internal static HttpResponseData Ok(this HttpRequestData req, string contents) => req.PlainTextResult(HttpStatusCode.OK, contents);

    /// <summary>
    /// Returns a <see cref="HttpStatusCode.InternalServerError"/> response with the provided text response.
    /// </summary>
    /// <param name="req">The <see cref="HttpRequestData"/> request to return the response for.</param>
    /// <param name="contents">The text content to return.</param>
    /// <returns>A <see cref="HttpResponseData"/> response indicating an internal server error with the provided text content.</returns>
    internal static HttpResponseData InternalServerError(this HttpRequestData req, string contents) => req.PlainTextResult(HttpStatusCode.InternalServerError, contents);


    internal static async Task<(bool Success, HttpResponseData? Error)> TryValidateEntries(this HttpRequestData req, IAsyncEnumerable<PwnedPasswordsIngestionValue?> entries)
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

    public static HttpResponseData PlainTextResult(this HttpRequestData req, HttpStatusCode statusCode, string content)
    {
        var res = req.CreateResponse(statusCode);
        res.WriteString(content);
        return res;
    }
}
