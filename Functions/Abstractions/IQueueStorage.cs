// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace HaveIBeenPwned.PwnedPasswords.Abstractions;

public interface IQueueStorage
{
    Task PushTransactionAsync(QueueTransactionEntry entry, CancellationToken cancellationToken = default);
    Task PushPasswordsAsync(QueuePasswordEntry[] entry, CancellationToken cancellationToken = default);
}
