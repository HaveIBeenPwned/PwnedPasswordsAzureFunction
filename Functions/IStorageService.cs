using System.Threading.Tasks;

namespace Functions
{
    public interface IStorageService
    {
        Task<BlobStorageEntry?> GetByHashesByPrefix(string hashPrefix);
    }
}