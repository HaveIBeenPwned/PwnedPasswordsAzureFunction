using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Functions
{
    /// <summary>
    /// Hash utility functions to create and validate hashes
    /// </summary>
    public static class Hash
    {
        private static readonly char[] HexChars = new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        private static readonly SHA1 Hasher = new SHA1Managed();
        private static readonly object HashLock = new object();

        /// <summary>
        /// Create a SHA-1 hash
        /// </summary>
        /// <param name="input"></param>
        /// <param name="source">Source encoding. Defaults to UTF-8. Pass in any other value for Unicode</param>
        /// <returns>The input string as a SHA-1 hash</returns>
        public static string CreateSHA1Hash(this string input, string source = "UTF8")
        {
            if (input == null)
            {
                return null;
            }

            var bytes = source == "UTF8" ? Encoding.UTF8.GetBytes(input) : Encoding.Unicode.GetBytes(input);
            byte[] hash;
            
            // SHA1.ComputeHash is not thread safe, so let's lock. It's still quicker than creating a new instance each time.
            lock (HashLock)
            {
                hash = Hasher.ComputeHash(bytes);
            }

            var hexChars = new char[hash.Length * 2];
            int index = 0;
            for (int i = 0; i < hash.Length; i++)
            {
                hexChars[index++] = HexChars[(hash[i] >> 4) & 0b1111];
                hexChars[index++] = HexChars[(hash[i]) & 0b1111];
            }

            return new string(hexChars);
        }

        /// <summary>
        /// Check that the string is a valid SHA-1 hash with regex
        /// </summary>
        /// <param name="input">Input hash to check</param>
        /// <returns>Boolean representing if the input is valid or not</returns>
        public static bool IsStringSHA1Hash(this string input) => input.IsHexStringOfLength(40);
        
        public static bool IsHexStringOfLength(this string input, int requiredLength)
        {
            if (string.IsNullOrWhiteSpace(input) || input?.Length != requiredLength)
            {
                return false;
            }

            for (int i = 0; i < requiredLength; i++)
            {
                if (!input[i].IsHex())
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Check that the string is a valid NTLM hash with regex
        /// </summary>
        /// <param name="input">Input hash to check</param>
        /// <returns>Boolean representing if the input is valid or not</returns>
        public static bool IsStringNTLMHash(this string input) => input.IsHexStringOfLength(32);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsHex(this char x) => (x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F');
    }
}
