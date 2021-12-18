using System;
using System.IO;

namespace HaveIBeenPwned.PwnedPasswords.Models
{
    public readonly struct PwnedPasswordsFile
    {
        public byte[] Content { get; }
        public DateTimeOffset LastModified { get; }
        public string ETag { get; }

        public PwnedPasswordsFile(byte[] content, DateTimeOffset lastModified, string etag)
        {
            Content = content;
            LastModified = lastModified;
            ETag = etag;
        }
    }
}
