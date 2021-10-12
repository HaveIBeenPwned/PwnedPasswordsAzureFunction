using System;
using System.IO;

using Azure;

namespace HaveIBeenPwned.PwnedPasswords.Models
{
    /// <summary>
    /// Blob storage entry
    /// </summary>
    public class BlobStorageEntry
    {
        public Stream Stream { get; }
        public DateTimeOffset LastModified { get; }
        public ETag ETag { get; }

        public BlobStorageEntry(Stream stream, DateTimeOffset lastModified, ETag etag)
        {
            Stream = stream;
            LastModified = lastModified;
            ETag = etag;
        }
    }
}
