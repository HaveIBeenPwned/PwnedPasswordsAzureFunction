using System.Net.Http;
using System.Net.Http.Json;

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
        // We can max purge 30 uris at a time.
        var filesToPurge = new List<string>(30);

        for (int i = 0; i < hashPrefixes.Count; i++)
        {
            filesToPurge.Add(new UriBuilder(_options.Value.PwnedPasswordsBaseUrl) { Path = $"range/{hashPrefixes[i]}" }.Uri.GetComponents(UriComponents.Host | UriComponents.Path, UriFormat.SafeUnescaped));
            if (filesToPurge.Count == 30)
            {
                string[] items = [.. filesToPurge];
                await ProcessQueueItem(items, cancellationToken).ConfigureAwait(false);

                filesToPurge.Clear();
            }
        }

        if (filesToPurge.Count > 0)
        {
            string[] items = [.. filesToPurge];
            await ProcessQueueItem(items, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessQueueItem(string[] items, CancellationToken cancellationToken = default)
    {
        _log.LogInformation("Purging the following prefixes from Cloudflare Cache: {URIs}", string.Join(", ", items));
        using (HttpResponseMessage response = await _httpClient.PostAsJsonAsync(string.Empty, new { prefixes = items }, cancellationToken).ConfigureAwait(false))
        {
            try
            {
                JsonDocument result = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken).ConfigureAwait(false);
                bool success = result.RootElement.GetProperty("success").GetBoolean();

                if (success)
                {
                    _log.LogInformation("Purged {NumItems} files from Cloudflare Cache.", items.Length);
                }
                else
                {
                    _log.LogError("Cloudflare purge failed. Result: {Result}", result);
                }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Cloudflare purge failed.");
            }
        }
    }
}
