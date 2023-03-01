using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using Xunit;

namespace HaveIBeenPwned.PwnedPasswords.Tests;

public class RangeTests
{
    private static readonly ILogger<Functions.Range> s_nullLogger = NullLoggerFactory.Instance.CreateLogger<Functions.Range>();

    [Fact]
    public async Task Returns_ok_given_valid_hashprefix()
    {
        string validHashPrefix = "ABCDE";
        var returnHashFile = new PwnedPasswordsFile(Stream.Null, DateTimeOffset.UtcNow, "\"ABCDEF\"");
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(validHashPrefix, "sha1", CancellationToken.None)).ReturnsAsync(returnHashFile);

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        HttpResponseMessage actualResponse = await function.RunAsync(context.Request, validHashPrefix);
        Assert.Equal(HttpStatusCode.OK, actualResponse.StatusCode);
    }

    [Fact]
    public async Task Returns_notfound_if_hashprefix_doesnt_exist()
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ThrowsAsync(new FileNotFoundException());

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        HttpResponseMessage actualResponse = await function.RunAsync(context.Request, "ABCDE");
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
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1",CancellationToken.None)).ReturnsAsync(default(PwnedPasswordsFile));

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        HttpResponseMessage actualResponse = await function.RunAsync(context.Request, invalidHashPrefix);
        Assert.Equal(HttpStatusCode.BadRequest, actualResponse.StatusCode);
    }

    [Fact]
    public async Task Returns_internal_server_error_when_something_goes_wrong()
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ThrowsAsync(new Exception());

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        HttpResponseMessage actualResponse = await function.RunAsync(context.Request, "ABCDE");
        Assert.Equal(HttpStatusCode.InternalServerError, actualResponse.StatusCode);
    }
}
