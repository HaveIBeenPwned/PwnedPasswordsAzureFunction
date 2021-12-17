// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion
{
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
        [FunctionName("IngestionSubmit")]
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
                (bool Success, IActionResult? Error) = await req.TryValidateEntries(JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(req.Body));
                if (Success)
                {
                    // Now insert the data
                    req.Body.Seek(0, System.IO.SeekOrigin.Begin);
                    PwnedPasswordsTransaction? transaction = await _tableStorage.InsertAppendDataAsync(subscriptionId).ConfigureAwait(false);
                    await _fileStorage.StoreIngestionFileAsync(transaction.TransactionId, req.Body).ConfigureAwait(false);
                    return new OkObjectResult(transaction);
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
}
