using System;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;

using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Functions
{
    /// <summary>
    /// Main entry point for Pwned Passwords
    /// </summary>
    public class Range
    {
        private readonly IStorageService _blobStorage;
        private readonly ILogger<Range> _log;

        /// <summary>
        /// Pwned Passwords - Range handler
        /// </summary>
        /// <param name="blobStorage">The Blob storage</param>
        public Range(IStorageService blobStorage, ILogger<Range> log)
        {
            _blobStorage = blobStorage;
            _log = log;
        }

        /// <summary>
        /// Handle a request to /range/{hashPrefix}
        /// </summary>
        /// <param name="req">The request message from the client</param>
        /// <param name="hashPrefix">The passed hash prefix</param>
        /// <param name="log">Logger instance to emit diagnostic information to</param>
        /// <returns></returns>
        [Function("Range-GET")]
        public async Task<HttpResponseData> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "range/{hashPrefix}")] HttpRequestData req, string hashPrefix)
        {
            TelemetryClient? telemetryClient = req.FunctionContext.InstanceServices.GetService<TelemetryClient>();
            using (IOperationHolder<RequestTelemetry>? requestTelemetry = telemetryClient?.StartOperation<RequestTelemetry>(req.FunctionContext.FunctionDefinition.Name))
            {
                if (requestTelemetry is not null)
                {
                    Activity.Current?.SetParentId(req.FunctionContext.TraceContext.TraceParent);
                    requestTelemetry.Telemetry.Context.Operation.ParentId = Activity.Current?.ParentId;
                    requestTelemetry.Telemetry.Url = req.Url;
                    req.FunctionContext.Features.Set(requestTelemetry.Telemetry);
                }

                if (!hashPrefix.IsHexStringOfLength(5))
                {
                    return BadRequest(req);
                }

                try
                {
                    BlobStorageEntry? entry = await _blobStorage.GetHashesByPrefix(hashPrefix.ToUpper());
                    return entry == null ? NotFound(req) : File(req, entry);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Something went wrong.");
                    return InternalServerError(req);
                }
            }
        }

        private static HttpResponseData BadRequest(HttpRequestData req)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.BadRequest);
            response.WriteString("The hash prefix was not in a valid format");
            RequestTelemetry? telemetry = req.FunctionContext.Features.Get<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = false;
                telemetry.ResponseCode = "400";
            }

            return response;
        }

        private static HttpResponseData NotFound(HttpRequestData req)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.NotFound);
            response.WriteString("The hash prefix was not found");
            RequestTelemetry? telemetry = req.FunctionContext.Features.Get<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = false;
                telemetry.ResponseCode = "404";
            }

            return response;
        }

        private static HttpResponseData File(HttpRequestData req, BlobStorageEntry entry)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add(HeaderNames.LastModified, entry.LastModified.ToString("R"));
            response.Body = entry.Stream;
            RequestTelemetry? telemetry = req.FunctionContext.Features.Get<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = true;
                telemetry.ResponseCode = "200";
            }

            return response;
        }

        private static HttpResponseData InternalServerError(HttpRequestData req)
        {
            HttpResponseData response = req.CreateResponse(HttpStatusCode.InternalServerError);
            response.WriteString("Something went wrong.");
            RequestTelemetry? telemetry = req.FunctionContext.Features.Get<RequestTelemetry>();
            if (telemetry is not null)
            {
                telemetry.Success = false;
                telemetry.ResponseCode = "500";
            }

            return response;
        }
    }
}
