namespace HaveIBeenPwned.PwnedPasswords.Models;

public readonly struct PwnedPasswordsFile
{
    public Stream Content { get; }
    public DateTimeOffset LastModified { get; }
    public string ETag { get; }

    public PwnedPasswordsFile(Stream content, DateTimeOffset lastModified, string etag)
    {
        Content = content;
        LastModified = lastModified;
        ETag = etag;
    }
}
