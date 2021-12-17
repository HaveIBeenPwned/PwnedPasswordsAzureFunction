// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace HaveIBeenPwned.PwnedPasswords.Abstractions
{
    public interface ICdnStorage
    {
        /// <summary>
        /// Purges the provided list of hash prefixes from the CDN cache.
        /// </summary>
        /// <param name="hashPrefixes">The list of hash prefixes to purge.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>An awaitable <see cref="Task"/></returns>
        Task PurgeFilesAsync(List<string> hashPrefixes, CancellationToken cancellationToken = default);
    }
}
