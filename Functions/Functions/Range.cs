using System.IO.Pipelines;

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
            return req.BadRequest("The hash format was not in a valid format");
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

            if (mode == "sha1")
            {
                return new FileStreamResult(entry.Content, "text/plain") { LastModified = entry.LastModified };
            }
            else
            {
                // Reading the NTLM hashes as a binary blob and returning the data in clear-text.
                var pipe = new Pipe();
                var pipeReader = PipeReader.Create(entry.Content);
                int i = 0;
                int numEntries = (int)entry.Content.Length / 18;
                await foreach (HashEntry item in HashEntry.ParseBinaryHashEntries(hashPrefix, 16, pipeReader))
                {
                    i++;
                    item.WriteTextTo(pipe.Writer, true);
                    if (i != numEntries)
                    {
                        Encoding.UTF8.GetBytes("\r\n", pipe.Writer);
                    }
                }
                await pipe.Writer.FlushAsync();
                await pipe.Writer.CompleteAsync();

                return new FileStreamResult(pipe.Reader.AsStream(), "text/plain") { LastModified = entry.LastModified };
            }
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
