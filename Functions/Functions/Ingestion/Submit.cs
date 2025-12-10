// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

/// <summary>
/// Pwned Passwords - Append handler
/// </summary>
/// <param name="blobStorage">The Blob storage</param>
public class Submit(ILogger<Submit> log, ITableStorage tableStorage, IFileStorage fileStorage)
{
    private const string SubscriptionIdHeaderKey = "Api-Subscription-Id";

    /// <summary>
    /// Handle a request to /range/append
    /// </summary>
    /// <param name="req">The request message from the client</param>
    /// <param name="log">Trace writer to use to write to the log</param>
    /// <returns>Response to the requesting client</returns>
    [Function("IngestionSubmit")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "append")] HttpRequest req)
    {
        // Check that the data has been passed as JSON
        if (req.ContentType == null || !req.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
        {
            // Incorrect Content-Type, bad request
            return req.BadRequest("Content-Type must be application/json");
        }

        string subscriptionId = req.Headers[SubscriptionIdHeaderKey].ToString();
        if (string.IsNullOrEmpty(subscriptionId))
        {
            return req.BadRequest("Api-Subscription-Id header missing or invalid");
        }

        Activity.Current?.AddTag("SubscriptionId", subscriptionId);
        try
        {
            (bool Success, IActionResult Error) = await req.TryValidateEntries(JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(req.Body)).ConfigureAwait(false);
            if (Success)
            {
                // Now insert the data
                req.Body.Seek(0, SeekOrigin.Begin);
                PwnedPasswordsTransaction transaction = await tableStorage.InsertAppendDataAsync(subscriptionId).ConfigureAwait(false);
                await fileStorage.StoreIngestionFileAsync(transaction.TransactionId, req.Body).ConfigureAwait(false);
                return new OkObjectResult(transaction);
            }

            return Error!;
        }
        catch (JsonException e)
        {
            // Error occurred trying to deserialize the JSON payload.
            log.LogError(e, "Unable to parse JSON for subscription {SubscriptionId}", subscriptionId);
            return req.BadRequest($"Unable to parse JSON: {e.Message}");
        }
    }
}
