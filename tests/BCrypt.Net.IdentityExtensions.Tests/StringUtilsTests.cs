using BCryptNet.IdentityExtensions;

namespace BCrypt.Net.IdentityExtensions.Tests;

public sealed class StringUtilsTests
{
    [Fact]
    public void FromBase64_Returns_Empty_On_Invalid_Input()
    {
        var result = "not-base64".FromBase64();

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ToHex_Returns_Lowercase_Hex()
    {
        var result = StringUtils.ToHex([0, 1, 2, 255]);
        Assert.Equal("000102ff", result);
    }

    [Fact]
    public void ToHex_Returns_Empty_On_Null_Input()
    {
        var result = StringUtils.ToHex(null);

        Assert.Equal(string.Empty, result);
    }
}
