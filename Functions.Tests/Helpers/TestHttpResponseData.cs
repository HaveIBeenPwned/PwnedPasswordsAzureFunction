using System.IO;
using System.Net;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

using Moq;

namespace Functions.Tests
{
    public class TestHttpResponseData : HttpResponseData
    {
        public TestHttpResponseData(FunctionContext functionContext, HttpStatusCode status) : this(functionContext)
        {
            StatusCode = status;
        }

        public TestHttpResponseData(FunctionContext functionContext) : base(functionContext)
        {
        }

        public override HttpStatusCode StatusCode { get; set; }
        public override HttpHeadersCollection Headers { get; set; } = new HttpHeadersCollection();
        public override Stream Body { get; set; } = Stream.Null;
        public override HttpCookies Cookies { get; } = Mock.Of<HttpCookies>();
    }
}
