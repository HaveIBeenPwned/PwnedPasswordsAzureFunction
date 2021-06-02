using System.Configuration;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs.Host;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Functions
{
    /// <summary>
    /// Cloudflare instance to perform actions
    /// </summary>
    public sealed class Cloudflare
    {
        private const string CLOUDFLARE_URL = "https://api.cloudflare.com/client/v4/";
        private const string PURGE_FILE = CLOUDFLARE_URL + "zones/{0}/purge_cache";

        private const string PWNEDPASSWORDS_URL = "https://api.pwnedpasswords.com";

        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly TraceWriter _log;
        private readonly string _email;
        private readonly string _apiKey;
        private readonly string _zoneIdentifier;

        /// <summary>
        /// Create a new instance of the Cloudflare wrapper
        /// </summary>
        /// <param name="log">Log to use</param>
        public Cloudflare(TraceWriter log)
        {
            _log = log;
            _email = ConfigurationManager.AppSettings["CloudflareAPIEmail"];
            _apiKey = ConfigurationManager.AppSettings["CloudflareAPIKey"];
            _zoneIdentifier = ConfigurationManager.AppSettings["CloudflareZoneIdentifier"];

            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.Add("X-Auth-Email", _email);
            _httpClient.DefaultRequestHeaders.Add("X-Auth-Key", _apiKey);
        }

        /// <summary>
        /// Deletes the given hash prefixes from Cloudflare caches.
        /// See <a href="https://api.cloudflare.com/#zone-purge-files-by-url">Cloudflare documentation</a> for purge_cache 
        /// </summary>
        /// <param name="hashPrefixes">Array of hash prefixes</param>
        /// <returns>Boolean stating if Cloudflare returned a success in the JSON response</returns>
        public async Task<bool> PurgeFile(string[] hashPrefixes)
        {
            if (!CanMakeCloudflareRequest())
            {
                _log.Warning("Unable to make Cloudflare request due to missing configuration values");
                return false;
            }

            var urlArray = new JArray();
            for (int i = 0; i < hashPrefixes.Length; i++)
            {
                urlArray.Add($"{PWNEDPASSWORDS_URL}/range/{hashPrefixes[i]}");
            }

            var requestContent = JsonConvert.SerializeObject(urlArray);

            var url = string.Format(PURGE_FILE, _zoneIdentifier);

            var sw = Stopwatch.StartNew();
            var response = await _httpClient.PostAsJsonAsync(url, requestContent);
            sw.Stop();

            var content = await response.Content.ReadAsStringAsync();

            var result = JObject.Parse(content);
            var success = result.Value<bool>("success");

            if (success)
            {
                _log.Info($"Purging {hashPrefixes.Length} files from Cloudflare Cache took {sw.ElapsedMilliseconds:n0}ms");
            }
            else
            {
                _log.Error($"Cloudflare Request failed in {sw.ElapsedMilliseconds:n0}ms");
                _log.Error(content);
            }

            return success;
        }

        /// <summary>
        /// Check if a Cloudflare request can be made
        /// </summary>
        /// <returns>True if we have a populated API key and Zone identifier</returns>
        private bool CanMakeCloudflareRequest()
        {
            return !string.IsNullOrEmpty(_email) && !string.IsNullOrEmpty(_apiKey) && !string.IsNullOrEmpty(_zoneIdentifier);
        }
    }
}
