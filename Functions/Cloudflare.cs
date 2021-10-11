using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace HaveIBeenPwned.PwnedPasswords
{
    /// <summary>
    /// Cloudflare instance to perform actions
    /// </summary>
    public sealed class Cloudflare
    {
        private static readonly HttpClient s_httpClient = new();
        private readonly ILogger _log;
        private readonly string _pwnedPasswordsUrl;

        /// <summary>
        /// Create a new instance of the Cloudflare wrapper
        /// </summary>
        /// <param name="log">Log to use</param>
        public Cloudflare(IConfiguration configuration, ILogger<Cloudflare> log)
        {
            _pwnedPasswordsUrl = configuration["PwnedPasswordsBaseUrl"];
            if(string.IsNullOrEmpty(_pwnedPasswordsUrl))
            {
                throw new KeyNotFoundException("\"PwnedPasswordsBaseUrl\" has not been configured.");
            }

            string apiToken = configuration["CloudflareAPIToken"];
            if(string.IsNullOrEmpty(apiToken))
            {
                throw new KeyNotFoundException("\"CloudflareAPIToken\" has not been configured.");
            }

            string zoneId = configuration["CloudflareZoneIdentifier"];
            if(string.IsNullOrEmpty(zoneId))
            {
                throw new KeyNotFoundException("\"CloudflareZoneIdentifier\" has not been configured.");

            }

            _log = log;
            s_httpClient.BaseAddress = new Uri($"https://api.cloudflare.com/client/v4/zones/{zoneId}/purge_cache");
            s_httpClient.DefaultRequestHeaders.Accept.Clear();
            s_httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            s_httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken); ;
        }

        /// <summary>
        /// Deletes the given hash prefixes from Cloudflare caches.
        /// See <a href="https://api.cloudflare.com/#zone-purge-files-by-url">Cloudflare documentation</a> for purge_cache 
        /// </summary>
        /// <param name="hashPrefixes">Array of hash prefixes</param>
        /// <returns>Boolean stating if Cloudflare returned a success in the JSON response</returns>
        public async Task<bool> PurgeFile(string[] hashPrefixes)
        {
            var filesToPurge = new { files = new List<string>(hashPrefixes.Length) };

            for (int i = 0; i < hashPrefixes.Length; i++)
            {
                filesToPurge.files[i] = new UriBuilder(_pwnedPasswordsUrl) { Path = $"range/{hashPrefixes[i]}" }.Uri.ToString();
            }

            string? requestContent = JsonSerializer.Serialize(filesToPurge);

            var sw = Stopwatch.StartNew();
            using (HttpResponseMessage? response = await s_httpClient.PostAsJsonAsync(string.Empty, requestContent))
            {
                sw.Stop();
                try
                {
                    JsonDocument? result = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                    bool success = result.RootElement.GetProperty("success").GetBoolean();

                    if (success)
                    {
                        _log.LogInformation($"Purging {hashPrefixes.Length} files from Cloudflare Cache took {sw.ElapsedMilliseconds:n0}ms");
                    }
                    else
                    {
                        _log.LogError($"Cloudflare Request failed in {sw.ElapsedMilliseconds:n0}ms");
                        _log.LogError(result.ToString());
                    }

                    return success;
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Cloudflare request failed.");
                    return false;
                }
            }
        }
    }
}
