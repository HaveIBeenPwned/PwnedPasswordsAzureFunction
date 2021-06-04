using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;

namespace Functions.Tests
{
    public class TestHttpRequestData : HttpRequestData
    {
        public TestHttpRequestData(FunctionContext functionContext, Stream body = null, string method = "GET", string url = null)
            : base(functionContext)
        {
            Body = body ?? new MemoryStream();
            Headers = new HttpHeadersCollection();
            Cookies = new List<IHttpCookie>();
            Url = new Uri(url ?? "https://localhost");
            Identities = new List<ClaimsIdentity>();
            Method = method;
        }

        public override Stream Body { get; }

        public override HttpHeadersCollection Headers { get; }

        public override IReadOnlyCollection<IHttpCookie> Cookies { get; }

        public override Uri Url { get; }

        public override IEnumerable<ClaimsIdentity> Identities { get; }

        public override string Method { get; }

        public override HttpResponseData CreateResponse()
        {
            var response = new TestHttpResponseData(this.FunctionContext);

            response.Body = new MemoryStream();
            response.Headers = new HttpHeadersCollection();

            return response;
        }
    }
}