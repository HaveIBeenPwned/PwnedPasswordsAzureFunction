namespace Functions
{
    public class BlobStorageOptions : IOptions<BlobStorageOptions>
    {
        public string BlobContainerName { get; set; }
        public BlobStorageOptions => this;
    }
}
