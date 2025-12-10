namespace HaveIBeenPwned.PwnedPasswords.Models;

public readonly struct PwnedPasswordsFile(Stream content, DateTimeOffset lastModified, string etag)
{
    public Stream Content { get; } = content;
    public DateTimeOffset LastModified { get; } = lastModified;
    public string ETag { get; } = etag;
}
