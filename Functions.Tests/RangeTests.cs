using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Functions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
        var returnHashFile = new PwnedPasswordsFile(Stream.Null, DateTimeOffset.UtcNow, "*");
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(validHashPrefix, "sha1", CancellationToken.None)).ReturnsAsync(returnHashFile);

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        IActionResult? actualResponse = await function.RunAsync(context.Request, validHashPrefix);

        Assert.IsType<PwnedPasswordsFileResult>(actualResponse);
    }

    [Fact]
    public async Task Returns_notfound_if_hashprefix_doesnt_exist()
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ThrowsAsync(new FileNotFoundException());

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        IActionResult? actualResponse = await function.RunAsync(context.Request, "ABCDE");

        ContentResult? result = Assert.IsType<ContentResult>(actualResponse);
        Assert.Equal(StatusCodes.Status404NotFound, result.StatusCode);
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
        var context = new DefaultHttpContext();
        IActionResult? actualResponse = await function.RunAsync(context.Request, invalidHashPrefix);

        ContentResult? result = Assert.IsType<ContentResult>(actualResponse);
        Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
    }

    [Fact]
    public async Task Returns_internal_server_error_when_something_goes_wrong()
    {
        var mockStorage = new Mock<IFileStorage>();
        mockStorage.Setup(s => s.GetHashFileAsync(It.IsAny<string>(), "sha1", CancellationToken.None)).ThrowsAsync(new Exception());

        var function = new Functions.Range(s_nullLogger, mockStorage.Object);
        var context = new DefaultHttpContext();
        IActionResult? actualResponse = await function.RunAsync(context.Request, "ABCDE");

        ContentResult? result = Assert.IsType<ContentResult>(actualResponse);
        Assert.Equal(StatusCodes.Status500InternalServerError, result.StatusCode);
    }
}
