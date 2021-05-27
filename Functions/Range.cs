using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;

namespace Functions
{
  /// <summary>
  /// Main entry point for Pwned Passwords
  /// </summary>
  public static class Range
  {
    /// <summary>
    /// Handle a request to /range/{hashPrefix}
    /// </summary>
    /// <param name="req">The request message from the client</param>
    /// <param name="hashPrefix">The passed hash prefix</param>
    /// <param name="log">Trace writer to use to write to the log</param>
    /// <returns></returns>
    [FunctionName("Range-GET")]
    public static HttpResponseMessage RunRoute([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestMessage req, string hashPrefix, TraceWriter log)
    {
      return GetData(req, hashPrefix, log);
    }

    /// <summary>
    /// Get the data for 
    /// </summary>
    /// <param name="req">The request message from the client</param>
    /// <param name="hashPrefix">The passed hash prefix</param>
    /// <param name="log">Trace writer to use to write to the log</param>
    /// <returns></returns>
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

      BlobStorage storage = new BlobStorage(log);
      var stream = storage.GetByHashesByPrefix(hashPrefix.ToUpper(), out var lastModified);
      var response = PwnedResponse.CreateResponse(req, HttpStatusCode.OK, null, stream, lastModified);
      return response;
    }
  }
}
