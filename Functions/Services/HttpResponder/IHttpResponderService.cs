using Microsoft.Azure.Functions.Worker.Http;
using System;
using System.Threading.Tasks;

namespace Functions.Services.HttpResponder
{
    public interface IHttpResponderService
    {
        Task<HttpResponseData> BadRequest(HttpRequestData httpRequest, string message);
        Task<HttpResponseData> InternalServerError(HttpRequestData httpRequest, string message);
        Task<HttpResponseData> Ok(HttpRequestData httpRequest, byte[] content, DateTimeOffset? lastModified = null);
    }
}
