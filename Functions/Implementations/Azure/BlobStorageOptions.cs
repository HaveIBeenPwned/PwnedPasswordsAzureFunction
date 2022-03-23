namespace HaveIBeenPwned.PwnedPasswords.Implementations.Azure;

public class BlobStorageOptions : IOptions<BlobStorageOptions>
{
    public string BlobContainerName { get; set; } = "";
    public string ConnectionString { get; set; } = "";
    public BlobStorageOptions Value => this;
}
