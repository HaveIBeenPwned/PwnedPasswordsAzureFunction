// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

public class Confirm
{
    private const string SubscriptionIdHeaderKey = "Api-Subscription-Id";
    private readonly ILogger<Confirm> _log;
    private readonly ITableStorage _tableStorage;
    private readonly IQueueStorage _queueStorage;

    /// <summary>
    /// Pwned Passwords - Append handler
    /// </summary>
    /// <param name="blobStorage">The Blob storage</param>
    public Confirm(ILogger<Confirm> log, ITableStorage tableStorage, IQueueStorage queueStorage)
    {
        _log = log;
        _tableStorage = tableStorage;
        _queueStorage = queueStorage;
    }

    [FunctionName("IngestionConfirm")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "append/confirm")] HttpRequest req)
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
            PwnedPasswordsTransaction? data = await JsonSerializer.DeserializeAsync<PwnedPasswordsTransaction>(req.Body).ConfigureAwait(false);
            if (data != null && !string.IsNullOrEmpty(data.TransactionId))
            {
                Activity.Current?.AddTag("TransactionId", data.TransactionId);
                if (await _tableStorage.ConfirmAppendDataAsync(subscriptionId, data))
                {
                    await _queueStorage.PushTransactionAsync(new QueueTransactionEntry { SubscriptionId = subscriptionId, TransactionId = data.TransactionId });
                }

                return new StatusCodeResult(StatusCodes.Status200OK);
            }

            return req.BadRequest("No content provided.");
        }
        catch (ArgumentOutOfRangeException) // Thrown if transaction is not found.
        {
            return new ContentResult { StatusCode = StatusCodes.Status404NotFound, Content = "TransactionId not found.", ContentType = "text/plain" };
        }
        catch (ArgumentException) // Thrown if trying to confirm transaction multiple times as the same time
        {
            return new ContentResult { StatusCode = StatusCodes.Status409Conflict, Content = "TransactionId is already being confirmed.", ContentType = "text/plain" };
        }
        catch (InvalidOperationException) // Thrown for other errors
        {
            return new ContentResult { StatusCode = StatusCodes.Status500InternalServerError, Content = "An error occurred.", ContentType = "text/plain" };
        }
        catch (JsonException e)
        {
            // Error occurred trying to deserialize the JSON payload.
            _log.LogError(e, "Unable to parson JSON");
            return req.BadRequest($"Unable to parse JSON: {e.Message}");
        }
    }
}
