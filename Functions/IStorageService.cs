using System.Threading.Tasks;

namespace Functions
{
    public interface IStorageService
    {
        Task<BlobStorageEntry?> GetHashesByPrefix(string hashPrefix);

        Task UpdateBlobFile(string hashPrefix, string hashPrefixFileContents);
    }
}
