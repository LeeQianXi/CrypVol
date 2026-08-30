using CrypVol.Lib;
using CrypVol.Lib.Volume;
using Xunit;

namespace CrypVol.Tests;

public class FileEntryHeaderIntegrityTests
{
    [Fact]
    public void SetGet_RoundTrip_AllValues()
    {
        foreach (var level in Enum.GetValues<IntegrityLevel>())
        {
            var header = new FileEntryHeader();
            header.SetIntegrityLevel(level);
            Assert.Equal(level, header.GetIntegrityLevel());
        }
    }

    [Fact]
    public void SetIntegrityLevel_PreservesFragmentFlags()
    {
        var header = new FileEntryHeader { Flags = 3 };
        header.SetIntegrityLevel(IntegrityLevel.Block);

        Assert.Equal(3, header.Flags & 3);
        Assert.Equal(IntegrityLevel.Block, header.GetIntegrityLevel());
    }

    [Fact]
    public void ToBytes_PreservesIntegrityLevel()
    {
        var header = new FileEntryHeader();
        header.SetIntegrityLevel(IntegrityLevel.File);

        Assert.Equal(IntegrityLevel.File, (IntegrityLevel)(header.ToBytes()[12] >> 3 & 3));
    }
}
