
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
    public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequest req, string hashPrefix, CancellationToken cancellationToken = default)
    {
        if (!hashPrefix.IsHexStringOfLength(5))
        {
            return req.BadRequest("The hash was not in a valid format");
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
            return new PwnedPasswordsFileResult(entry);
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

public class PwnedPasswordsFileResult : IActionResult
{
    private readonly PwnedPasswordsFile _pwnedPasswordsFile;

    public PwnedPasswordsFileResult(PwnedPasswordsFile pwnedPasswordsFile)
    {
        _pwnedPasswordsFile = pwnedPasswordsFile;
    }

    public async Task ExecuteResultAsync(ActionContext context)
    {
        context.HttpContext.Response.StatusCode = 200;
        context.HttpContext.Response.ContentType = "text/plain";
        context.HttpContext.Response.ContentLength = _pwnedPasswordsFile.Content.Length;
        context.HttpContext.Response.Headers["Last-Modified"] = _pwnedPasswordsFile.LastModified.ToString("R");
        context.HttpContext.Response.Headers["ETag"] = _pwnedPasswordsFile.ETag;

        // NOTE: This flush should deactivate buffering
        await context.HttpContext.Response.Body.FlushAsync(context.HttpContext.RequestAborted);
        await _pwnedPasswordsFile.Content.CopyToAsync(context.HttpContext.Response.Body, context.HttpContext.RequestAborted);
        await _pwnedPasswordsFile.Content.DisposeAsync();
    }
}
