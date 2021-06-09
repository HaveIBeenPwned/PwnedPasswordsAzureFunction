using Functions;
using Xunit;

namespace Tests
{
    public class HashTests
    {
        [Theory]
        [InlineData("", false)]
        [InlineData("123", true)]
        [InlineData("OHNO!", false)]
        [InlineData("0BADF00D", true)]
        [InlineData("0bAdF00D", true)]
        public void IsHexString(string input, bool isHex)
        {
            Assert.Equal(isHex, input.IsHexStringOfLength(input?.Length ?? 0));
        }

        [Theory]
        [InlineData("Passw0rd!", "F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D")]
        [InlineData("hunter2", "F3BBBD66A63D4BF1747940578EC3D0103530E21D")]
        public void CreateSHA1Hash(string input, string expected)
        {
            Assert.Equal(expected, Hash.CreateSHA1Hash(input));
        }

        [Theory]
        [InlineData("", 0, false)]
        [InlineData("01", 2, true)]
        [InlineData("aB", 2, true)]
        [InlineData("F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D", 40, true)]
        [InlineData("F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D", 39, false)]
        [InlineData("F4A69", 5, true)]
        public void IsHexStringOfLength(string input, int length, bool expected)
        {
            Assert.Equal(expected, input.IsHexStringOfLength(length));
        }

        [Theory]
        [InlineData("F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D", true)]
        [InlineData("F3BBBD66A63D4BF1747940578EC3D0103530E21D", true)]
        [InlineData("f4A69973E7B0BF9D160f9f60E3C3ACD2494BEB0D", true)]
        [InlineData("f3bbBD66A63D4BF1747940578EC3D0103530E21D", true)]
        [InlineData("G3BBBD66A63D4BF1747940578EC3D0103530E21D", false)]
        [InlineData("F3BBBD66A63D4BF1747940578EC3D0103530E21DAA", false)]
        [InlineData("31D6CFE0D16AE931B73C59D7E0C089C0", false)]
        [InlineData("", false)]
        public void IsSHA1Hash(string input, bool expected)
        {
            Assert.Equal(expected, input.IsStringSHA1Hash());
        }

        [Theory]
        [InlineData("31d6cfe0d16ae931b73c59d7e0c089c0", true)]
        [InlineData("31D6CFE0D16AE931B73C59D7E0C089C0", true)]
        [InlineData("31D6CFE0D16AE931B73C59D7E0C089C0A", false)]
        [InlineData("G1D6CFE0D16AE931B73C59D7E0C089C0", false)]
        [InlineData("31D6CFE0D16AE931B73C59D7E0C089C", false)]
        [InlineData("F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D", false)]
        [InlineData("", false)]
        public void IsNTLMHash(string input, bool expected)
        {
            Assert.Equal(expected, input.IsStringNTLMHash());
        }
    }
}
