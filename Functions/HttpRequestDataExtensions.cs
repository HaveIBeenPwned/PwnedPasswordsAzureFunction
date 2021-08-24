using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Functions
{
    internal static class HttpRequestDataExtensions
    {
        /// <summary>
        /// Gets the <typeparamref name="TService"/> from the
        /// <c>HttpRequestData.FunctionContext.Features</c> object.
        /// </summary>
        /// <typeparam name="TService">The service type to get.</typeparam>
        /// <param name="req">The <see cref="HttpRequestData"/> instance in context.</param>
        /// <returns>The <typeparamref name="TService"/> if resolved.</returns>
        internal static TService? GetFeatureService<TService>(this HttpRequestData req) =>
            req.FunctionContext.Features.Get<TService>();

        /// <summary>
        /// Gets the <typeparamref name="TService"/> from the
        /// <c>HttpRequestData.FunctionContext.InstanceServices</c> collection.
        /// </summary>
        /// <typeparam name="TService">The service type to get.</typeparam>
        /// <param name="req">The <see cref="HttpRequestData"/> instance in context.</param>
        /// <returns>The <typeparamref name="TService"/> if resolved.</returns>
        internal static TService? GetInstanceService<TService>(this HttpRequestData req) =>
            req.FunctionContext.InstanceServices.GetService<TService>();
    }
}
