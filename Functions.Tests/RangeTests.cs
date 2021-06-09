using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
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
            var dummyLogger = NullLoggerFactory.Instance.CreateLogger<Range>();
            var returnHashFile = new BlobStorageEntry(Stream.Null, DateTimeOffset.Parse(lastModified));

            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(validHashPrefix, CancellationToken.None)).ReturnsAsync(returnHashFile);

            var function = new Range(mockStorage.Object, dummyLogger);

            var actualResponse = await function.RunAsync(request, validHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.OK);
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
            var dummyLogger = NullLoggerFactory.Instance.CreateLogger<Range>();

            var function = new Range(mockStorage.Object, dummyLogger);

            var actualResponse = await function.RunAsync(request, invalidHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Returns_internal_server_error_when_something_goes_wrong()
        {
            var validHashPrefix = "ABCDE";
            var request = new TestHttpRequestData(new TestFunctionContext());
            var dummyLogger = NullLoggerFactory.Instance.CreateLogger<Range>();

            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ThrowsAsync(new Exception());

            var function = new Range(mockStorage.Object, dummyLogger);

            var actualResponse = await function.RunAsync(request, validHashPrefix);

            actualResponse.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        }
    }
}
