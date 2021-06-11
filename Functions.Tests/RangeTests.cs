using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using FluentAssertions;

using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using Xunit;

namespace Functions.Tests
{
    public class RangeTests
    {
        private static readonly ILogger<Range> s_nullLogger = NullLoggerFactory.Instance.CreateLogger<Range>();

        [Fact]
        public async Task Returns_ok_given_valid_hashprefix()
        {
            string validHashPrefix = "ABCDE";
            var request = new TestHttpRequestData(new TestFunctionContext());
            var returnHashFile = new BlobStorageEntry(Stream.Null, DateTimeOffset.UtcNow);
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(validHashPrefix, CancellationToken.None)).ReturnsAsync(returnHashFile);

            var function = new Range(mockStorage.Object, s_nullLogger);
            HttpResponseData actualResponse = await function.RunAsync(request, validHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task Returns_notfound_if_hashprefix_doesnt_exist()
        {
            var request = new TestHttpRequestData(new TestFunctionContext());
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ReturnsAsync(default(BlobStorageEntry));

            var function = new Range(mockStorage.Object, s_nullLogger);
            HttpResponseData actualResponse = await function.RunAsync(request, "ABCDE");

            actualResponse.StatusCode.Should().Be(HttpStatusCode.NotFound);
        }

        [Theory]
        [InlineData("")]
        [InlineData("123456")]
        [InlineData("ABCDG")]
        [InlineData("ghijk")]
        public async Task Returns_bad_request_given_invalid_hashprefix(string invalidHashPrefix)
        {
            var request = new TestHttpRequestData(new TestFunctionContext());
            var mockStorage = new Mock<IStorageService>();

            var function = new Range(mockStorage.Object, s_nullLogger);
            HttpResponseData actualResponse = await function.RunAsync(request, invalidHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Returns_internal_server_error_when_something_goes_wrong()
        {
            string validHashPrefix = "ABCDE";
            var request = new TestHttpRequestData(new TestFunctionContext());
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ThrowsAsync(new Exception());

            var function = new Range(mockStorage.Object, s_nullLogger);
            HttpResponseData actualResponse = await function.RunAsync(request, validHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        }
    }
}
