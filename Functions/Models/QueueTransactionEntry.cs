﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Text;

namespace HaveIBeenPwned.PwnedPasswords.Models
{
    public class QueueTransactionEntry
    {
        public string SubscriptionId { get; set; } = "";
        public string TransactionId { get; set; } = "";
    }
}
