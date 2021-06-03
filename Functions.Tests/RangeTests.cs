using FluentAssertions;
using Functions.Dtos;
using Functions.Services.HttpResponder;
using Functions.Services.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Net.Http.Headers;
using Moq;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Functions.Tests
{
    public class RangeTests
    {
        [Fact]
        public async Task Returns_ok_given_valid_hashprefix()
        {
            var validHashPrefix = "ABCDE";
            var lastModified = "Fri, 01 Jan 2021 00:00:00 GMT";
            var request = new TestHttpRequestData(new TestFunctionContext());
            var responderService = new DefaultHttpResponderService();
            var nullLogger = NullLoggerFactory.Instance.CreateLogger<Range>();
            var returnHashFile = new HashFile()
            {
                Content = Array.Empty<byte>(),
                LastModified = DateTimeOffset.Parse(lastModified)
            };

            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(validHashPrefix, CancellationToken.None)).ReturnsAsync(returnHashFile);

            var function = new Range(responderService, mockStorage.Object, nullLogger);

            var actualResponse = await function.RunRoute(request, validHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.OK);

            actualResponse.Headers.GetValues(HeaderNames.ContentType).Should().BeEquivalentTo(new string[] { "text/plain" });
            actualResponse.Headers.GetValues(HeaderNames.AccessControlAllowOrigin).Should().BeEquivalentTo(new string[] { "*" });
            actualResponse.Headers.GetValues(HeaderNames.CacheControl).Should().ContainMatch("*public*max-age=*");
            actualResponse.Headers.GetValues(HeaderNames.LastModified).Should().BeEquivalentTo(new string[] { lastModified });
            actualResponse.Headers.GetValues(ExtendedHeaderNames.ArrDisableSessionAffinity).Should().BeEquivalentTo(new string[] { "True" });
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("123456")]
        [InlineData("ABCDG")]
        [InlineData("ghijk")]
        public async Task Returns_bad_request_given_invalid_hashprefix(string invalidHashPrefix)
        {
            var request = new TestHttpRequestData(new TestFunctionContext());
            var responderService = new DefaultHttpResponderService();
            var nullLogger = NullLoggerFactory.Instance.CreateLogger<Range>();

            var function = new Range(responderService, null, nullLogger);

            var actualResponse = await function.RunRoute(request, invalidHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Returns_internal_server_error_when_something_goes_wrong()
        {
            var validHashPrefix = "ABCDE";

            var request = new TestHttpRequestData(new TestFunctionContext());
            var responderService = new DefaultHttpResponderService();
            var nullLogger = NullLoggerFactory.Instance.CreateLogger<Range>();

            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ThrowsAsync(new System.Exception());

            var function = new Range(responderService, mockStorage.Object, nullLogger);

            var actualResponse = await function.RunRoute(request, validHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        }
    }
}
