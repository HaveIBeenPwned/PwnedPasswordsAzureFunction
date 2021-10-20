using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare
{
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
        public CdnStorage(IOptions<CdnStorageOptions> options, ILogger<CdnStorage> log, HttpClient httpClient)
        {
            _options = options;
            _log = log;
            _httpClient = httpClient;
        }

        /// <summary>
        /// Deletes the given hash prefixes from Cloudflare caches.
        /// See <a href="https://api.cloudflare.com/#zone-purge-files-by-url">Cloudflare documentation</a> for purge_cache 
        /// </summary>
        /// <param name="hashPrefixes">Array of hash prefixes</param>
        /// <returns>Boolean stating if Cloudflare returned a success in the JSON response</returns>
        public async Task PurgeFilesAsync(List<string> hashPrefixes, CancellationToken cancellationToken = default)
        {
            async Task SendPurgeCommand(List<string> urisToPurge, CancellationToken cancellationToken = default)
            {
                using (HttpResponseMessage? response = await _httpClient.PostAsJsonAsync(string.Empty, new { files = urisToPurge }, cancellationToken))
                {
                    try
                    {
                        JsonDocument? result = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(), cancellationToken: cancellationToken);
                        bool success = result.RootElement.GetProperty("success").GetBoolean();

                        if (success)
                        {
                            _log.LogInformation($"Purged {urisToPurge.Count} files from Cloudflare Cache.");
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

            // We can max purge 30 uris at a time.
            var filesToPurge = new List<string>(30);

            for (int i = 0; i < hashPrefixes.Count; i++)
            {
                filesToPurge.Add(new UriBuilder(_options.Value.PwnedPasswordsBaseUrl) { Path = $"range/{hashPrefixes[i]}" }.Uri.ToString());
                if (filesToPurge.Count == 30)
                {
                    await SendPurgeCommand(filesToPurge, cancellationToken);
                    filesToPurge.Clear();
                }
            }

            if (filesToPurge.Count > 0)
            {
                await SendPurgeCommand(filesToPurge, cancellationToken);
            }
        }
    }
}
