// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare;

public class CdnStorageOptions : IOptions<CdnStorageOptions>
{
    public string APIToken { get; set; } = "";
    public string ZoneIdentifier { get; set; } = "";
    public string PwnedPasswordsBaseUrl { get; set; } = "";
    public CdnStorageOptions Value => this;
}
