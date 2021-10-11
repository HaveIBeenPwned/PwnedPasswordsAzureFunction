using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace HaveIBeenPwned.PwnedPasswords
{
    /// <summary>
    /// Hash utility functions to create and validate hashes
    /// </summary>
    public static class Hash
    {
        /// <summary>
        /// Create a SHA-1 hash
        /// </summary>
        /// <param name="input"></param>
        /// <param name="source">Source encoding. Defaults to UTF-8. Pass in any other value for Unicode</param>
        /// <returns>The input string as a SHA-1 hash</returns>
        public static string CreateSHA1Hash(this string input, string source = "UTF8")
        {
            Encoding encoding = source == "UTF8" ? Encoding.UTF8 : Encoding.Unicode;
            Span<byte> hash = stackalloc byte[20];
            _ = SHA1.HashData(encoding.GetBytes(input), hash);
            return Convert.ToHexString(hash);
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
