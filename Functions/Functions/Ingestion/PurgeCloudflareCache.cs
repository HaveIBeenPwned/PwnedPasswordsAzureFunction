// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Azure.Functions.Worker;

namespace HaveIBeenPwned.PwnedPasswords.Functions.Ingestion;

public class PurgeCloudflareCache
{
    private readonly ILogger _log;
    private readonly ITableStorage _tableStorage;
    private readonly ICdnStorage _cdnStorage;

    /// <summary>
    /// Pwned Passwords - Append handler
    /// </summary>
    /// <param name="blobStorage">The Blob storage</param>
    public PurgeCloudflareCache(ILogger<PurgeCloudflareCache> log, ITableStorage tableStorage, ICdnStorage cdnStorage)
    {
        _log = log;
        _tableStorage = tableStorage;
        _cdnStorage = cdnStorage;
    }
    #region Timer Functions

    /// <summary>
    /// Updates the contents of the Azure Storage Blobs from the Azure Storage Table data.
    /// This currently runs every day at 30 minutes past midnight.
    /// </summary>
    /// <param name="timer">Timer information</param>
    /// <param name="log">Logger</param>
    [Function("PurgeCloudflareCache")]
    public async Task Run(
#if DEBUG
        // IMPORTANT: Do *not* enable RunOnStartup in production as it can result in excessive cost
        // See: https://blog.tdwright.co.uk/2018/09/06/beware-runonstartup-in-azure-functions-a-serverless-horror-story/
        [TimerTrigger("0 30 0 * * *", RunOnStartup = true)]
#else
            [TimerTrigger("0 30 0 * * *")]
#endif
            TimerInfo timer, CancellationToken cancellationToken)
    {
        if (timer.ScheduleStatus == null)
        {
            _log.LogWarning("ScheduleStatus is null - this is required");
            return;
        }

        // Get a list of the partitions which have been modified
        List<string> modifiedPartitions = await _tableStorage.GetModifiedHashPrefixes(cancellationToken);

        if (modifiedPartitions.Count > 0)
        {
            await _cdnStorage.PurgeFilesAsync(modifiedPartitions, cancellationToken).ConfigureAwait(false);
            _log.LogInformation($"Successfully purged Cloudflare Cache.");
        }
        else
        {
            _log.LogInformation($"Detected no purges needed for Cloudflare cache.");
        }
    }
    #endregion
}
