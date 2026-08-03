using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib;
using Xunit;

namespace CrypVol.Tests;

public class Crc32Tests
{
    [Fact]
    public void KnownVector_Empty()
    {
        Assert.Equal(0x00000000u, Crc32.Compute(Array.Empty<byte>()));
    }

    [Fact]
    public void KnownVector_Hello()
    {
        // "hello" CRC32 = 0x3610A686 (verified against Python binascii.crc32)
        var data = Encoding.UTF8.GetBytes("hello");
        Assert.Equal(0x3610A686u, Crc32.Compute(data));
    }

    [Fact]
    public void KnownVector_123456789()
    {
        // "123456789" CRC32 = 0xCBF43926 (standard check value)
        var data = Encoding.UTF8.GetBytes("123456789");
        Assert.Equal(0xCBF43926u, Crc32.Compute(data));
    }

    [Fact]
    public void SameInput_SameOutput()
    {
        var data = new byte[1024];
        RandomNumberGenerator.Fill(data);
        Assert.Equal(Crc32.Compute(data), Crc32.Compute(data));
    }

    [Fact]
    public void DifferentInput_DifferentOutput()
    {
        var a = Encoding.UTF8.GetBytes("alpha");
        var b = Encoding.UTF8.GetBytes("beta");
        Assert.NotEqual(Crc32.Compute(a), Crc32.Compute(b));
    }

    [Fact]
    public void SingleByte_Differs_FromEmpty()
    {
        var empty = Crc32.Compute(Array.Empty<byte>());
        var single = Crc32.Compute(new byte[]
        {
            0
        });
        Assert.NotEqual(empty, single);
    }

    [Fact]
    public void LargeData_Consistent()
    {
        var data = new byte[100000];
        RandomNumberGenerator.Fill(data);
        var crc1 = Crc32.Compute(data);
        var crc2 = Crc32.Compute(data);
        Assert.Equal(crc1, crc2);
    }

    [Fact]
    public void OneBitFlip_ChangesCRC()
    {
        var data = new byte[256];
        RandomNumberGenerator.Fill(data);
        var original = Crc32.Compute(data);
        data[128] ^= 1;
        Assert.NotEqual(original, Crc32.Compute(data));
    }
}