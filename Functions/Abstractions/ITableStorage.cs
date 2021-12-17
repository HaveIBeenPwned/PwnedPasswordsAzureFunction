// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Models;

namespace HaveIBeenPwned.PwnedPasswords.Abstractions
{
    public interface ITableStorage
    {
        Task<PwnedPasswordsTransaction> InsertAppendDataAsync(string subscriptionId, CancellationToken cancellationToken = default);
        Task<bool> IsTransactionConfirmedAsync(string subscriptionId, string transactionId, CancellationToken cancellationToken = default);
        Task<List<PwnedPasswordsIngestionValue>> GetTransactionValuesAsync(string subscriptionId, string transactionId, CancellationToken cancellationToken = default);
        Task<bool> ConfirmAppendDataAsync(string subscriptionId, PwnedPasswordsTransaction transaction, CancellationToken cancellationToken = default);
        Task<bool> AddOrIncrementHashEntry(string subscriptionId, string transactionId, PwnedPasswordsIngestionValue value, CancellationToken cancellationToken = default);
        Task<List<string>> GetModifiedHashPrefixes(CancellationToken cancellationToken = default);
        Task MarkHashPrefixAsModified(string prefix, CancellationToken cancellationToken = default);
    }
}
