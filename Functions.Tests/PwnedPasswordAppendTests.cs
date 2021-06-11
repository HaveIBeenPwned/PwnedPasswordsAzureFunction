using Xunit;

namespace Functions.Tests
{
    public class PwnedPasswordAppendTests
    {
        [Theory]
        [InlineData("abcdef", "ABCDEF")]
        [InlineData("c5c375930174561a95fca5388b45abad802a19cd", "C5C375930174561A95FCA5388B45ABAD802A19CD")]
        public void UppercaseSHA1Hash(string hash, string upperHash)
        {
            PwnedPasswordAppend append = new() { SHA1Hash = hash };
            Assert.Equal(upperHash, append.SHA1Hash);
        }

        [Theory]
        [InlineData("abcdef", "ABCDEF")]
        [InlineData("b4b9b02e6f09a9bd760f388b67351e2b", "B4B9B02E6F09A9BD760F388B67351E2B")]
        public void UppercaseNTLMHash(string hash, string upperHash)
        {
            PwnedPasswordAppend append = new() { NTLMHash = hash };
            Assert.Equal(upperHash, append.NTLMHash);
        }

        [Theory]
        [InlineData("ABCDEF", "ABCDE")]
        [InlineData("c5c375930174561a95fca5388b45abad802a19cd", "C5C37")]
        public void PartitionKey(string hash, string partitionKey)
        {
            PwnedPasswordAppend append = new() { SHA1Hash = hash };
            Assert.Equal(partitionKey, append.PartitionKey);
        }

        [Theory]
        [InlineData("ABCDEFABC", "FABC")]
        [InlineData("c5c375930174561a95fca5388b45abad802a19cd", "5930174561A95FCA5388B45ABAD802A19CD")]
        public void RowKey(string hash, string rowKey)
        {
            PwnedPasswordAppend append = new() { SHA1Hash = hash };
            Assert.Equal(rowKey, append.RowKey);
        }
    }
}
