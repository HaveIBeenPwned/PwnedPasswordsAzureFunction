using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Net.Http.Headers;
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Functions.Services.HttpResponder
{
    public class DefaultHttpResponderService : IHttpResponderService
    {
        public async Task<HttpResponseData> BadRequest(HttpRequestData httpRequest, string message)
        {
            var response = httpRequest.CreateResponse(HttpStatusCode.BadRequest);
            return await WriteStringContentAsync(response, message);
        }

        public async Task<HttpResponseData> InternalServerError(HttpRequestData httpRequest, string message)
        {
            var response = httpRequest.CreateResponse(HttpStatusCode.InternalServerError);
            return await WriteStringContentAsync(response, message);
        }

        private async Task<HttpResponseData> WriteStringContentAsync(HttpResponseData response, string message)
        {
            response.Headers.Add(HeaderNames.ContentType, "text/plain");

            await response.WriteStringAsync(message ?? string.Empty, Encoding.UTF8);

            SetAdditionalHeaders(response);

            return response;
        }

        public async Task<HttpResponseData> Ok(HttpRequestData httpRequest, byte[] content, DateTimeOffset? lastModified = null)
        {
            var response = httpRequest.CreateResponse(HttpStatusCode.OK);

            if (content != null)
            {
                await response.WriteBytesAsync(content);
            }

            response.Headers.Add(HeaderNames.ContentType, "text/plain");

            if (lastModified != null)
            {
                response.Headers.Add(HeaderNames.LastModified, lastModified?.ToString("R"));
            }

            SetAdditionalHeaders(response);

            return response;
        }

        protected virtual void SetAdditionalHeaders(HttpResponseData httpResponseData)
        {
            httpResponseData.Headers.Add(HeaderNames.CacheControl, new string[] {
                $"max-age={TimeSpan.FromDays(31).TotalSeconds}",
                "public"
            });

            httpResponseData.Headers.Add("Arr-Disable-Session-Affinity", "True");
            httpResponseData.Headers.Add(HeaderNames.AccessControlAllowOrigin, "*");
        }
    }
}
