// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace HaveIBeenPwned.PwnedPasswords.Abstractions
{
    public interface ICdnStorage
    {
        Task PurgeFilesAsync(List<string> hashPrefixes, CancellationToken cancellationToken = default);
    }
}
