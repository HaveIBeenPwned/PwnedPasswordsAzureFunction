using System;
using System.IO;

namespace HaveIBeenPwned.PwnedPasswords.Models
{
    public readonly struct PwnedPasswordsFile
    {
        public Stream Stream { get; }
        public DateTimeOffset LastModified { get; }
        public string ETag { get; }

        public PwnedPasswordsFile(Stream stream, DateTimeOffset lastModified, string etag)
        {
            Stream = stream;
            LastModified = lastModified;
            ETag = etag;
        }
    }
}
