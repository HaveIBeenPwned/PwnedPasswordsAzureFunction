using System;
using System.IO;

namespace Functions
{
    /// <summary>
    /// Blob storage entry
    /// </summary>
    public class BlobStorageEntry
    {
        /// <summary>
        /// Stream representing the blob contents
        /// </summary>
        public Stream Stream { get; set; }
        
        /// <summary>
        /// Pointer to the DateTimeOffset for the last time that the blob was modified
        /// </summary>
        public DateTimeOffset? LastModified { get; set; }
    }
}
