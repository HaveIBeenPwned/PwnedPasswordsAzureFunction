// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System.Linq;
using System.Net;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

public class Submit
{
    private const string SubscriptionIdHeaderKey = "Api-Subscription-Id";
    private readonly ILogger<Submit> _log;
    private readonly ITableStorage _tableStorage;
    private readonly IFileStorage _fileStorage;

    /// <summary>
    /// Pwned Passwords - Append handler
    /// </summary>
    /// <param name="blobStorage">The Blob storage</param>
    public Submit(ILogger<Submit> log, ITableStorage tableStorage, IFileStorage fileStorage)
    {
        _log = log;
        _tableStorage = tableStorage;
        _fileStorage = fileStorage;
    }

    /// <summary>
    /// Handle a request to /range/append
    /// </summary>
    /// <param name="req">The request message from the client</param>
    /// <param name="log">Trace writer to use to write to the log</param>
    /// <returns>Response to the requesting client</returns>
    [Function("IngestionSubmit")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "append")] HttpRequestData req)
    {
        // Check that the data has been passed as JSON
        if (!req.Headers.TryGetValues("Content-Type", out var content) || content.Contains("application/json", StringComparer.OrdinalIgnoreCase))
        {
            // Incorrect Content-Type, bad request
            return req.BadRequest("Content-Type must be application/json");
        }

        if (!req.Headers.TryGetValues(SubscriptionIdHeaderKey, out var subIdHeader) || subIdHeader.Count() != 1 || string.IsNullOrEmpty(subIdHeader.First()))
        {
            return req.BadRequest("Api-Subscription-Id header missing or invalid");
        }

        string subscriptionId = subIdHeader.First();
        Activity.Current?.AddTag("SubscriptionId", subscriptionId);
        try
        {
            (bool Success, HttpResponseData? Error) = await req.TryValidateEntries(JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(req.Body));
            if (Success)
            {
                // Now insert the data
                req.Body.Seek(0, System.IO.SeekOrigin.Begin);
                PwnedPasswordsTransaction? transaction = await _tableStorage.InsertAppendDataAsync(subscriptionId).ConfigureAwait(false);
                await _fileStorage.StoreIngestionFileAsync(transaction.TransactionId, req.Body).ConfigureAwait(false);
                var res = req.CreateResponse(HttpStatusCode.OK);
                await res.WriteAsJsonAsync(transaction);
                return res;
            }

#pragma warning disable CS8603 // Won't be null if Success=false.
            return Error;
#pragma warning restore CS8603 // Possible null reference return.
        }
        catch (JsonException e)
        {
            // Error occurred trying to deserialize the JSON payload.
            _log.LogError(e, "Unable to parse JSON for subscription {SubscriptionId}", subscriptionId);
            return req.BadRequest($"Unable to parse JSON: {e.Message}");
        }
    }
}
