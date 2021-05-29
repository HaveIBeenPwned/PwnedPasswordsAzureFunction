using Functions.Dtos;
using System.Threading;
using System.Threading.Tasks;

namespace Functions.Services.Storage
{
    public interface IStorageService
    {
        Task<HashFile> GetHashesByPrefix(string hashPrefix, CancellationToken cancellationToken = default);
    }
}