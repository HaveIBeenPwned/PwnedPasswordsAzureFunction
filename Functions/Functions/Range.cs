
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.IO;

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

        HashType mode = HashType.SHA1;
        if (req.Query.TryGetValue("mode", out Microsoft.Extensions.Primitives.StringValues queryMode))

        {
            mode = (string)queryMode switch
            {
                "ntlm" => HashType.NTLM,
                _ => HashType.SHA1,
            };
        }

        try
        {
            PwnedPasswordsFile entry = await _fileStorage.GetHashFileAsync(hashPrefix.ToUpper(), mode, cancellationToken);
            return new PwnedPasswordsFileResult(entry, req.GetTypedHeaders().AcceptEncoding);
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
    private readonly IList<Microsoft.Net.Http.Headers.StringWithQualityHeaderValue> _acceptEncoding;
    private static readonly RecyclableMemoryStreamManager s_recyclableMemoryStreamManager = new RecyclableMemoryStreamManager();

    public PwnedPasswordsFileResult(PwnedPasswordsFile pwnedPasswordsFile, IList<Microsoft.Net.Http.Headers.StringWithQualityHeaderValue> acceptEncoding)
    {
        _pwnedPasswordsFile = pwnedPasswordsFile;
        _acceptEncoding = acceptEncoding;
    }

    public async Task ExecuteResultAsync(ActionContext context)
    {
        context.HttpContext.Response.StatusCode = 200;
        context.HttpContext.Response.ContentType = "text/plain";
        context.HttpContext.Response.Headers["Last-Modified"] = _pwnedPasswordsFile.LastModified.ToString("R");
        context.HttpContext.Response.Headers["ETag"] = _pwnedPasswordsFile.ETag;
        using MemoryStream tempStream = s_recyclableMemoryStreamManager.GetStream();
        using var pwnedStream = _pwnedPasswordsFile.Content;
        if (_acceptEncoding.Any(x => x.Value == "br"))
        {
            using var brotliStream = new BrotliStream(tempStream, CompressionMode.Compress, true);
            context.HttpContext.Response.Headers["Content-Encoding"] = "br";
            await pwnedStream.CopyToAsync(brotliStream);
        }
        else if (_acceptEncoding.Any(x => x.Value == "gzip"))
        {
            using var gzipStream = new GZipStream(tempStream, CompressionMode.Compress, true);
            context.HttpContext.Response.Headers["Content-Encoding"] = "gzip";
            await pwnedStream.CopyToAsync(gzipStream);
        }
        else if (_acceptEncoding.Any(x => x.Value == "deflate"))
        {
            using var deflateStream = new DeflateStream(tempStream, CompressionMode.Compress, true);
            context.HttpContext.Response.Headers["Content-Encoding"] = "deflate";
            await pwnedStream.CopyToAsync(deflateStream);
        }
        else
        {
            await pwnedStream.CopyToAsync(tempStream);
        }

        tempStream.Seek(0, SeekOrigin.Begin);
        context.HttpContext.Response.ContentLength = tempStream.Length;
        await tempStream.CopyToAsync(context.HttpContext.Response.Body, context.HttpContext.RequestAborted);
    }
}
