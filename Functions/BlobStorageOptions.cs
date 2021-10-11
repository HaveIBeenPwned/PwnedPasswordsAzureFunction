
using Microsoft.Extensions.Options;

namespace HaveIBeenPwned.PwnedPasswords
{
    public class BlobStorageOptions : IOptions<BlobStorageOptions>
    {
        public string? BlobContainerName { get; set; }
        public BlobStorageOptions Value => this;
    }
}
