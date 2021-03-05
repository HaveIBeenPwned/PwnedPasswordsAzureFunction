using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
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
  }
}
