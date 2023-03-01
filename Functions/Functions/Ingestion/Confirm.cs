// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using System.Net;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

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

    [Function("IngestionConfirm")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post", Route = "append/confirm")] HttpRequestData req)
    {
        // Check that the data has been passed as JSON
        if (!req.Headers.TryGetValues("Content-Type", out var content) || content.Contains("application/json", StringComparer.OrdinalIgnoreCase))
        {
            // Incorrect Content-Type, bad request
            return req.BadRequest("Content-Type must be application/json");
        }

        if(!req.Headers.TryGetValues(SubscriptionIdHeaderKey, out var subIdHeader) || subIdHeader.Count() != 1 || string.IsNullOrEmpty(subIdHeader.First())) 
        {
            return req.BadRequest("Api-Subscription-Id header missing or invalid");
        }

        string subscriptionId = subIdHeader.First();
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

                return req.CreateResponse(HttpStatusCode.OK);
            }

            return req.BadRequest("No content provided.");
        }
        catch (ArgumentOutOfRangeException) // Thrown if transaction is not found.
        {
            return req.NotFound("TransactionId not found.");
        }
        catch (ArgumentException) // Thrown if trying to confirm transaction multiple times as the same time
        {
            return req.PlainTextResult(HttpStatusCode.Conflict, "TransactionId is already being confirmed.");
        }
        catch (InvalidOperationException) // Thrown for other errors
        {
            return req.InternalServerError("An error occurred.");
        }
        catch (JsonException e)
        {
            // Error occurred trying to deserialize the JSON payload.
            _log.LogError(e, "Unable to parson JSON");
            return req.BadRequest($"Unable to parse JSON: {e.Message}");
        }
    }
}
