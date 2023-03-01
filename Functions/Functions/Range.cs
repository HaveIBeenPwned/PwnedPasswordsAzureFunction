
using System.Globalization;
using System.Net;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Primitives;

namespace HaveIBeenPwned.PwnedPasswords.Functions;

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
    [Function("Range-GET")]
    public async Task<HttpResponseData> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestData req, string hashPrefix, FunctionContext executionContext, CancellationToken cancellationToken)
    {
        if (!hashPrefix.IsHexStringOfLength(5))
        {
            return req.BadRequest("The hash was not in a valid format");
        }

        string mode = "sha1";
        Dictionary<string, StringValues> query = QueryHelpers.ParseQuery(req.Url.Query);
        if (query.TryGetValue("mode", out StringValues queryMode))

        {
            mode = (string)queryMode switch
            {
                "ntlm" => "ntlm",
                _ => "sha1",
            };
        }

        try
        {
            PwnedPasswordsFile entry = await _fileStorage.GetHashFileAsync(hashPrefix.ToUpper(), mode, cancellationToken);
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain");
            response.Headers.Add("Content-Length", entry.Content.Length.ToString(CultureInfo.InvariantCulture));
            response.Headers.Add("ETag", entry.ETag);
            response.Headers.Add("Last-Modified", entry.LastModified.ToString("R"));
            await entry.Content.CopyToAsync(response.Body);
            return response;
        }
        catch (FileNotFoundException)
        {
            return req.NotFound("The hash prefix was not found");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Something went wrong.");
            return req.InternalServerError();
        }
    }
}
