using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace HaveIBeenPwned.PwnedPasswords
{
    /// <summary>
    /// Hash utility functions to create and validate hashes
    /// </summary>
    public static class Hash
    {
        private static readonly ThreadLocal<SHA1> s_sha1 = new ThreadLocal<SHA1>(SHA1.Create);
        private static SHA1 SHA1Hasher => s_sha1?.Value ?? SHA1.Create();
        private static readonly char[] s_hexChars = new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

        /// <summary>
        /// Create a SHA-1 hash
        /// </summary>
        /// <param name="input"></param>
        /// <param name="source">Source encoding. Defaults to UTF-8. Pass in any other value for Unicode</param>
        /// <returns>The input string as a SHA-1 hash</returns>
        public static string CreateSHA1Hash(this string input, string source = "UTF8")
        {
            Encoding encoding = source == "UTF8" ? Encoding.UTF8 : Encoding.Unicode;
            Span<char> hashChars = stackalloc char[40];
            byte[] hash = SHA1Hasher.ComputeHash(encoding.GetBytes(input));
            for (int i = 0; i < 20; i++)
            {
                int hashIndex = i * 2;
                byte x = hash[i];
                hashChars[hashIndex] = s_hexChars[(x >> 4) & 0xF];
                hashChars[hashIndex + 1] = s_hexChars[(x) & 0x0F];
            }

            return new string(hashChars);
        }

        /// <summary>
        /// Check that the string is a valid SHA-1 hash with regex
        /// </summary>
        /// <param name="input">Input hash to check</param>
        /// <returns>Boolean representing if the input is valid or not</returns>
        public static bool IsStringSHA1Hash(this string input) => input.IsHexStringOfLength(40);

        public static bool IsHexStringOfLength(this string input, int requiredLength)
        {
            if (input.Length == 0 || input.Length != requiredLength)
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
