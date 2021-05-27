using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Functions
{
  public static class Hash
  {
    public static string CreateSHA1Hash(string input, string source = "UTF8")
    {
      if (input == null)
      {
        return null;
      }

      using (var sha1 = new SHA1Managed())
      {
        var bytes = source == "UTF8" ? Encoding.UTF8.GetBytes(input) : Encoding.Unicode.GetBytes(input);
        var hash = sha1.ComputeHash(bytes);
        var sb = new StringBuilder(hash.Length * 2);

        foreach (var b in hash)
        {
          sb.Append(b.ToString("X2"));
        }

        return sb.ToString().ToUpper();
      }
    }

    public static bool IsStringSHA1Hash(string input)
    {
      if (string.IsNullOrWhiteSpace(input))
      {
        return false;
      }

      var regex = new Regex(@"\b([a-fA-F0-9]{40})\b");
      var match = regex.Match(input);
      return match.Length > 0;
    }

        /// <summary>
        /// Check that the string is a valid NTLM hash with regex
        /// </summary>
        /// <param name="input">Input hash to check</param>
        /// <returns>Boolean representing if the input is valid or not</returns>
        public static bool IsStringNTLMHash(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return false;
            }

            var match = Regex.Match(input, @"\b([a-fA-F0-9]{32})\b");
            return match.Length > 0;
        }
  }
}
