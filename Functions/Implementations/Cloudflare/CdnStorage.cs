using System.Net.Http;
using System.Threading.Channels;

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare;

/// <summary>
/// Cloudflare instance to perform actions
/// </summary>
public sealed class CdnStorage : ICdnStorage
{
    private readonly ILogger _log;
    private readonly HttpClient _httpClient;
    private readonly IOptions<CdnStorageOptions> _options;

    /// <summary>
    /// Create a new instance of the Cloudflare wrapper
    /// </summary>
    /// <param name="log">Log to use</param>
    public CdnStorage(IOptions<CdnStorageOptions> options, ILogger<CdnStorage> log, IHttpClientFactory httpClientFactory)
    {
        _options = options;
        _log = log;
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.BaseAddress = new Uri($"https://api.cloudflare.com/client/v4/zones/{options.Value.ZoneIdentifier}/purge_cache");
        _httpClient.DefaultRequestHeaders.Accept.Clear();
        _httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", options.Value.APIToken);
        _httpClient.DefaultRequestVersion = new Version(2, 0);
    }

    /// <summary>
    /// Deletes the given hash prefixes from Cloudflare caches.
    /// See <a href="https://api.cloudflare.com/#zone-purge-files-by-url">Cloudflare documentation</a> for purge_cache 
    /// </summary>
    /// <param name="hashPrefixes">Array of hash prefixes</param>
    /// <returns>Boolean stating if Cloudflare returned a success in the JSON response</returns>
    public async Task PurgeFilesAsync(List<string> hashPrefixes, CancellationToken cancellationToken = default)
    {
        Channel<string[]> channel = Channel.CreateBounded<string[]>(new BoundedChannelOptions(Startup.Parallelism) { FullMode = BoundedChannelFullMode.Wait, SingleReader = false, SingleWriter = true });
        Task[] queueTasks = new Task[Startup.Parallelism];
        for (int i = 0; i < queueTasks.Length; i++)
        {
            queueTasks[i] = ProcessQueueItem(channel, cancellationToken);
        }

        // We can max purge 30 uris at a time.
        var filesToPurge = new List<string>(30);

        for (int i = 0; i < hashPrefixes.Count; i++)
        {
            filesToPurge.Add(new UriBuilder(_options.Value.PwnedPasswordsBaseUrl) { Path = $"range/{hashPrefixes[i]}" }.Uri.GetComponents(UriComponents.Host | UriComponents.Path, UriFormat.SafeUnescaped));
            if (filesToPurge.Count == 30)
            {
                string[] items = filesToPurge.ToArray();
                if (!channel.Writer.TryWrite(items))
                {
                    await channel.Writer.WriteAsync(items, cancellationToken);
                }

                filesToPurge.Clear();
            }
        }

        if (filesToPurge.Count > 0)
        {
            string[] items = filesToPurge.ToArray();
            if (!channel.Writer.TryWrite(items))
            {
                await channel.Writer.WriteAsync(items, cancellationToken);
            }
        }

        channel.Writer.TryComplete();
        await Task.WhenAll(queueTasks);
    }

    private async Task ProcessQueueItem(Channel<string[]> channel, CancellationToken cancellationToken)
    {
        while (await channel.Reader.WaitToReadAsync(cancellationToken))
        {
            if (channel.Reader.TryRead(out string[]? urisToPurge) && urisToPurge != null)
            {
                _log.LogInformation("Purging the following prefixes from Cloudflare Cache: {URIs}", string.Join(", ", urisToPurge));
                using (HttpResponseMessage? response = await _httpClient.PostAsJsonAsync(string.Empty, new { prefixes = urisToPurge }, cancellationToken))
                {
                    try
                    {
                        JsonDocument? result = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
                        bool success = result.RootElement.GetProperty("success").GetBoolean();

                        if (success)
                        {
                            _log.LogInformation($"Purged {urisToPurge.Length} files from Cloudflare Cache.");
                        }
                        else
                        {
                            _log.LogError($"Cloudflare purge failed. Result: {result}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Cloudflare purge failed.");
                    }
                }
            }
        }
    }
}
