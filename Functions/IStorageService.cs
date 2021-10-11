using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Azure;

using HaveIBeenPwned.PwnedPasswords.Models;

namespace HaveIBeenPwned.PwnedPasswords
{
    public interface IStorageService
    {
        Task<BlobStorageEntry?> GetHashesByPrefix(string hashPrefix, CancellationToken cancellationToken = default);

        Task UpdateBlobFile(string hashPrefix, string hashPrefixFileContents);
        Task<bool> UpdateBlobFile(string hashPrefix, SortedDictionary<string, int> hashes, ETag etag);
    }
}
