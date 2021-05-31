using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Functions.UnitTests
{
    public class RangeTests
    {
        [Fact]
        public async Task Returns_bad_request_given_empty_hashprefix()
        {
            var req = ;
            var function = new Range(null, null, NullLoggerFactory.Instance.CreateLogger<Range>());

            var actualResponse = await function.RunRoute()
        }
    }
}
