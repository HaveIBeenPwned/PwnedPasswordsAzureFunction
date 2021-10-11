using System;
using System.IO;

using Azure;

namespace HaveIBeenPwned.PwnedPasswords.Models
{
    /// <summary>
    /// Blob storage entry
    /// </summary>
    public record BlobStorageEntry(Stream Stream, DateTimeOffset LastModified, ETag ETag);
}
