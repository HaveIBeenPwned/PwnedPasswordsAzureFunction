
using System.IO.Compression;
using System.Linq;

using Microsoft.IO;

namespace HaveIBeenPwned.PwnedPasswords.Functions;

/// <summary>
/// Main entry point for Pwned Passwords
/// </summary>
/// <remarks>
/// Pwned Passwords - Range handler
/// </remarks>
/// <param name="fileStorage">The file storage</param>
public class Range(ILogger<Range> log, IFileStorage fileStorage)
{

    /// <summary>
    /// Handle a request to /range/{hashPrefix}
    /// </summary>
    /// <param name="req">The request message from the client</param>
    /// <param name="hashPrefix">The passed hash prefix</param>
    /// <param name="log">Logger instance to emit diagnostic information to</param>
    /// <returns></returns>
    [Function("Range-GET")]
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
            PwnedPasswordsFile entry = await fileStorage.GetHashFileAsync(hashPrefix.ToUpper(), mode, cancellationToken).ConfigureAwait(false);
            return new PwnedPasswordsFileResult(entry, req.GetTypedHeaders().AcceptEncoding);
        }
        catch (FileNotFoundException)
        {
            return req.NotFound();
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Something went wrong.");
            return req.InternalServerError();
        }
    }
}

public class PwnedPasswordsFileResult(PwnedPasswordsFile pwnedPasswordsFile, IList<Microsoft.Net.Http.Headers.StringWithQualityHeaderValue> acceptEncoding) : IActionResult
{
    private static readonly RecyclableMemoryStreamManager s_recyclableMemoryStreamManager = new();

    public async Task ExecuteResultAsync(ActionContext context)
    {
        context.HttpContext.Response.StatusCode = 200;
        context.HttpContext.Response.ContentType = "text/plain";
        context.HttpContext.Response.Headers.LastModified = pwnedPasswordsFile.LastModified.ToString("R");
        context.HttpContext.Response.Headers.ETag = pwnedPasswordsFile.ETag;
        using RecyclableMemoryStream tempStream = s_recyclableMemoryStreamManager.GetStream();
        using Stream pwnedStream = pwnedPasswordsFile.Content;
        if (acceptEncoding.Any(x => x.Value == "br"))
        {
            using var brotliStream = new BrotliStream(tempStream, CompressionMode.Compress, true);
            context.HttpContext.Response.Headers.ContentEncoding = "br";
            await pwnedStream.CopyToAsync(brotliStream).ConfigureAwait(false);
        }
        else if (acceptEncoding.Any(x => x.Value == "gzip"))
        {
            using var gzipStream = new GZipStream(tempStream, CompressionMode.Compress, true);
            context.HttpContext.Response.Headers.ContentEncoding = "gzip";
            await pwnedStream.CopyToAsync(gzipStream).ConfigureAwait(false);
        }
        else if (acceptEncoding.Any(x => x.Value == "deflate"))
        {
            using var deflateStream = new DeflateStream(tempStream, CompressionMode.Compress, true);
            context.HttpContext.Response.Headers.ContentEncoding = "deflate";
            await pwnedStream.CopyToAsync(deflateStream).ConfigureAwait(false);
        }
        else
        {
            await pwnedStream.CopyToAsync(tempStream).ConfigureAwait(false);
        }

        tempStream.Seek(0, SeekOrigin.Begin);
        context.HttpContext.Response.ContentLength = tempStream.Length;
        await tempStream.CopyToAsync(context.HttpContext.Response.Body, context.HttpContext.RequestAborted).ConfigureAwait(false);
    }
}
