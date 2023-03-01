
using System.Net.Http;
using System.Net.Http.Headers;

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
    [FunctionName("Range-GET")]
    public async Task<HttpResponseMessage> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequest req, string hashPrefix, CancellationToken cancellationToken = default)
    {
        if (!hashPrefix.IsHexStringOfLength(5))
        {
            return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest) { Content = new StringContent("The hash was not in a valid format") };
        }

        string mode = "sha1";
        if (req.Query.TryGetValue("mode", out Microsoft.Extensions.Primitives.StringValues queryMode))

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
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StreamContent(entry.Content)
            };

            response.Content.Headers.ContentLength = entry.Content.Length;
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
            response.Content.Headers.LastModified = entry.LastModified;
            response.Headers.ETag = new EntityTagHeaderValue(entry.ETag, false);
            return response;
        }
        catch (FileNotFoundException)
        {
            return new HttpResponseMessage(System.Net.HttpStatusCode.NotFound) { Content = new StringContent("The hash prefix was not found") };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Something went wrong.");
            return new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError) { Content = new StringContent("Something went wrong.") };
        }
    }
}
