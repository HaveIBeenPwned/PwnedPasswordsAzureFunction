using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace Functions
{
  public static class Range
  {
    [FunctionName("Range-GET")]
    public static HttpResponseMessage RunRoute([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestMessage req, string hashPrefix, TraceWriter log)
    {
      return GetData(req, hashPrefix, log);
    }

    private static HttpResponseMessage GetData(HttpRequestMessage req, string hashPrefix, TraceWriter log)
    {
      if (string.IsNullOrEmpty(hashPrefix))
      {
        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing hash prefix");
      }

      var querystringRegex = new Regex("^[a-fA-F0-9]{5}$");
      var match = querystringRegex.Match(hashPrefix);
      if (match.Length == 0)
      {
        return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The hash prefix was not in a valid format");
      }

      var stream = new BlobStorage(log).GetByHashesByPrefix(hashPrefix.ToUpper(), out var lastModified);
      var response = PwnedResponse.CreateResponse(req, HttpStatusCode.OK, null, stream, lastModified);
      return response;
    }

        [FunctionName("AppendPwnedPassword")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "range/append")] HttpRequestMessage req, TraceWriter log)
        {
            // Check that the data has been passed as JSON
            if (req.Content.Headers.ContentType.MediaType.ToLower() != "application/json")
            {
                // Incorrect Content-Type, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Content-Type must be application/json");
            }

            // Get JSON POST request body
            PwnedPasswordAppend data = await req.Content.ReadAsAsync<PwnedPasswordAppend>();

            if (data == null)
            {
                // Json wasn't parsed from POST body, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing JSON body");
            }

            if (string.IsNullOrEmpty(data.SHA1Hash))
            {
                // Empty SHA-1 hash, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing SHA-1 hash");
            }
            if (!Hash.IsStringSHA1Hash(data.SHA1Hash))
            {
                // Invalid SHA-1 hash, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The SHA-1 hash was not in a valid format");
            }

            if (string.IsNullOrEmpty(data.NTLMHash))
            {
                // Empty NTLM hash, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing NTLM hash");
            }
            if (!Hash.IsStringNTLMHash(data.NTLMHash))
            {
                // Invalid NTLM hash, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "The NTLM hash was not in a valid format");
            }

            if (data.Prevalence <= 0)
            {
                // Prevalence not set or invalid value, bad request
                return PwnedResponse.CreateResponse(req, HttpStatusCode.BadRequest, "Missing or invalid prevalence value");
            }

            log.Info("Received valid Pwned Passwords append request");

            BlobStorage storage = new BlobStorage(log);
            bool? newEntry = storage.UpdateHash(data.SHA1Hash, data.Prevalence);
            if (newEntry == null)
            {
                // Returned null, that means that the item was unable to be added, internal server error
                return PwnedResponse.CreateResponse(req, HttpStatusCode.InternalServerError, "Unable to add entry to Pwned Passwords");
            }

            if (newEntry.Value)
            {
                log.Info("Added new entry to Pwned Passwords");
            }
            else
            {
                log.Info("Updated existing entry in Pwned Passwords");
            }

            return PwnedResponse.CreateResponse(req, HttpStatusCode.OK, newEntry.ToString());
        }
    }
}
