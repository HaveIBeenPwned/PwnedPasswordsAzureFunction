using System;
using System.IO;

namespace Functions
{
    /// <summary>
    /// Blob storage entry
    /// </summary>
    public record BlobStorageEntry(Stream Stream, DateTimeOffset LastModified)
    {
        public Stream Stream { get; init; } = Stream;
        public DateTimeOffset LastModified { get; init; } = LastModified;
    }
}
