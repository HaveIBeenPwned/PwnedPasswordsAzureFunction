using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Azure;

using FluentAssertions;

using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using Xunit;

namespace HaveIBeenPwned.PwnedPasswords.Tests
{
    public class RangeTests
    {
        private static readonly ILogger<Functions.Range> s_nullLogger = NullLoggerFactory.Instance.CreateLogger<Functions.Range>();

        [Fact]
        public async Task Returns_ok_given_valid_hashprefix()
        {
            string validHashPrefix = "ABCDE";
            var returnHashFile = new BlobStorageEntry(Stream.Null, DateTimeOffset.UtcNow, ETag.All);
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(validHashPrefix, CancellationToken.None)).ReturnsAsync(returnHashFile);

            var function = new Functions.Range(mockStorage.Object, s_nullLogger);
            var context = new DefaultHttpContext();
            var actualResponse = await function.RunAsync(context.Request, validHashPrefix);

            Assert.IsType<FileStreamResult>(actualResponse);
        }

        [Fact]
        public async Task Returns_notfound_if_hashprefix_doesnt_exist()
        {
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ReturnsAsync(default(BlobStorageEntry));

            var function = new Functions.Range(mockStorage.Object, s_nullLogger);
            var context = new DefaultHttpContext();
            var actualResponse = await function.RunAsync(context.Request, "ABCDE");

            var result = Assert.IsType<ContentResult>(actualResponse);
            Assert.Equal(StatusCodes.Status404NotFound, result.StatusCode);
        }

        [Theory]
        [InlineData("")]
        [InlineData("123456")]
        [InlineData("ABCDG")]
        [InlineData("ghijk")]
        public async Task Returns_bad_request_given_invalid_hashprefix(string invalidHashPrefix)
        {
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ReturnsAsync(default(BlobStorageEntry));

            var function = new Functions.Range(mockStorage.Object, s_nullLogger);
            var context = new DefaultHttpContext();
            var actualResponse = await function.RunAsync(context.Request, invalidHashPrefix);

            var result = Assert.IsType<ContentResult>(actualResponse);
            Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
        }

        [Fact]
        public async Task Returns_internal_server_error_when_something_goes_wrong()
        {
            var mockStorage = new Mock<IStorageService>();
            mockStorage.Setup(s => s.GetHashesByPrefix(It.IsAny<string>(), CancellationToken.None)).ThrowsAsync(new Exception());

            var function = new Functions.Range(mockStorage.Object, s_nullLogger);
            var context = new DefaultHttpContext();
            var actualResponse = await function.RunAsync(context.Request, "ABCDE");

            var result = Assert.IsType<ContentResult>(actualResponse);
            Assert.Equal(StatusCodes.Status500InternalServerError, result.StatusCode);
        }
    }
}
