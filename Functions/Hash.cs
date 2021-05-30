using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Functions
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

    /// <summary>
    /// Check that the string is a valid SHA-1 hash with regex
    /// </summary>
    /// <param name="input">Input hash to check</param>
    /// <returns>Boolean representing if the input is valid or not</returns>
    public static bool IsStringSHA1Hash(string input)
    {
      if (string.IsNullOrWhiteSpace(input))
      {
        return false;
      }

      var match = Regex.Match(input, @"\b([a-fA-F0-9]{40})\b");
      return match.Length > 0;
    }
  }
}
