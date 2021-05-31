using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.IO;
using System.Net;

namespace Functions.Tests
{
    public class TestHttpResponseData : HttpResponseData
    {
        public TestHttpResponseData(FunctionContext functionContext, HttpStatusCode status)
            : this(functionContext)
        {
            StatusCode = status;
        }

        public TestHttpResponseData(FunctionContext functionContext) : base(functionContext)
        {

        }

        public override HttpStatusCode StatusCode { get; set; }
        public override HttpHeadersCollection Headers { get; set; }
        public override Stream Body { get; set; }
        public override HttpCookies Cookies { get; }
    }
}
