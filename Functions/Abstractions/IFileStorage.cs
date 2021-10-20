using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using HaveIBeenPwned.PwnedPasswords.Models;

namespace HaveIBeenPwned.PwnedPasswords.Abstractions
{
    public interface IFileStorage
    {
        /// <summary>
        /// Get a stream to the file using the hash prefix
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to lookup the file.</param>
        /// <returns>Returns a <see cref="PwnedPasswordsFile"/> with a stream to access the k-anonymity SHA-1 file, containing the last modified date and the file ETag.</returns>
        /// <exception cref="System.IO.FileNotFoundException" />
        Task<PwnedPasswordsFile> GetHashFileAsync(string hashPrefix, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates a hash file using the hash prefix.
        /// </summary>
        /// <param name="hashPrefix">The hash prefix to use to look up the file.</param>
        /// <param name="hashes">A sorted dictionary containing the hash prefixes as key and prevalence counts as value.</param>
        /// <param name="etag">The ETag of the existing file that can be checked to prevent update conflicts.</param>
        /// <param name="cancellationToken">A cancellation token to abort the update if signaled.</param>
        /// <returns>True of the file was successfully updated, otherwise false.</returns>
        Task<bool> UpdateHashFileAsync(string hashPrefix, SortedDictionary<string, int> hashes, string etag, CancellationToken cancellationToken = default);
    }
}
