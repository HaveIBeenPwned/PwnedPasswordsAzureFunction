using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using Xunit;

namespace HaveIBeenPwned.PwnedPasswords.Tests;

internal class TestFunctionContext : FunctionContext
{
    public override string InvocationId { get; }
    public override string FunctionId { get; }
    public override TraceContext TraceContext { get; }
    public override BindingContext BindingContext { get; }
    public override RetryContext RetryContext { get; }
    public override IServiceProvider InstanceServices { get; set; }
    public override FunctionDefinition FunctionDefinition { get; }
    public override IDictionary<object, object> Items { get; set; }
    public override IInvocationFeatures Features { get; }
}

internal class TestHttpRequestData : HttpRequestData
{
    public override Stream Body { get; } = Stream.Null;
    public override HttpHeadersCollection Headers { get; } = new HttpHeadersCollection();
    public override IReadOnlyCollection<IHttpCookie> Cookies { get; } = new Collection<IHttpCookie>();
    public override Uri Url { get; }
    public override IEnumerable<ClaimsIdentity> Identities { get; } = new Collection<ClaimsIdentity>();
    public override string Method { get; }

    public override HttpResponseData CreateResponse() => new TestHttpResponseData(base.FunctionContext);

    internal TestHttpRequestData(string method, Uri url) : base(new TestFunctionContext())
    {
        Method = method;
        Url = url;
    }
}

internal class TestHttpResponseData : HttpResponseData
{
    public TestHttpResponseData(FunctionContext functionContext) : base(functionContext)
    {
    }

    public override HttpStatusCode StatusCode { get; set; }
    public override HttpHeadersCollection Headers { get; set; } = new HttpHeadersCollection();
    public override Stream Body { get; set; } = Stream.Null;
    public override HttpCookies Cookies { get; } = new TestHttpCookies();
}

internal class TestHttpCookies : HttpCookies
{
    private readonly List<IHttpCookie> _cookies = new List<IHttpCookie>();
    public override void Append(string name, string value) => _cookies.Add(new HttpCookie(name, value));
    public override void Append(IHttpCookie cookie) => _cookies.Add(cookie);
    public override IHttpCookie CreateNew() => new HttpCookie("", "");
}

public class RangeTests
{
    private static readonly ILogger<Functions.Range> s_nullLogger = NullLoggerFactory.Instance.CreateLogger<Functions.Range>();

    [Fact]
    public async Task Returns_ok_given_valid_hashprefix()
    {
        string validHashPrefix = "ABCDE";
        var returnHashFile = new PwnedPasswordsFile(Stream.Null, DateTimeOffset.UtcNow, "\"0BADF00D\"");
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(validHashPrefix, "sha1", CancellationToken.None)).ReturnsAsync(returnHashFile);

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        HttpResponseData actualResponse = await function.RunAsync(new TestHttpRequestData("GET", new Uri($"https://test/range/{validHashPrefix}")), validHashPrefix);
        Assert.Equal(HttpStatusCode.OK, actualResponse.StatusCode);
    }

    [Fact]
    public async Task Returns_notfound_if_hashprefix_doesnt_exist()
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ThrowsAsync(new FileNotFoundException());

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        HttpResponseData actualResponse = await function.RunAsync(new TestHttpRequestData("GET", new Uri("https://test/range/ABCDE")), "ABCDE");
        Assert.Equal(HttpStatusCode.NotFound, actualResponse.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("123456")]
    [InlineData("ABCDG")]
    [InlineData("ghijk")]
    public async Task Returns_bad_request_given_invalid_hashprefix(string invalidHashPrefix)
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ReturnsAsync(default(PwnedPasswordsFile));

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        HttpResponseData actualResponse = await function.RunAsync(new TestHttpRequestData("GET", new Uri($"https://test/range/{invalidHashPrefix}")), invalidHashPrefix);
        Assert.Equal(HttpStatusCode.BadRequest, actualResponse.StatusCode);
    }

    [Fact]
    public async Task Returns_internal_server_error_when_something_goes_wrong()
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ThrowsAsync(new Exception());

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        HttpResponseData actualResponse = await function.RunAsync(new TestHttpRequestData("GET", new Uri("https://test/range/ABCDE")), "ABCDE");
        Assert.Equal(HttpStatusCode.InternalServerError, actualResponse.StatusCode);
    }
}
