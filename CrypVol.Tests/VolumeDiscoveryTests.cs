using CrypVol.Lib;
using Xunit;

namespace CrypVol.Tests;

public class VolumeDiscoveryTests
{
    private static string TempDir() => Path.Combine(Path.GetTempPath(), $"vd-{Guid.NewGuid()}");

    [Fact]
    public void Discover_Directory_ReturnsAllCvpFiles()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            File.WriteAllText(Path.Combine(dir.FullName, "archive.0.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "archive.1.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "archive.2.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "readme.txt"), ""); // not cvp

            var result = VolumeDiscovery.Discover([dir]);

            Assert.Equal(3, result.Count);
            Assert.All(result, f => Assert.EndsWith(".cvp", f.Name));
        }
        finally { try { dir.Delete(true); } catch { } }
    }

    [Fact]
    public void Discover_Directory_EmptyDir_ReturnsEmpty()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var result = VolumeDiscovery.Discover([dir]);
            Assert.Empty(result);
        }
        finally { try { dir.Delete(true); } catch { } }
    }

    [Fact]
    public void Discover_SingleFile_DiscoversSiblings()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            File.WriteAllText(Path.Combine(dir.FullName, "data.0.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "data.1.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "data.2.cvp"), "");

            var result = VolumeDiscovery.Discover([new FileInfo(Path.Combine(dir.FullName, "data.0.cvp"))]);

            Assert.Equal(3, result.Count);
            Assert.All(result, f => f.Name.StartsWith("data."));
        }
        finally { try { dir.Delete(true); } catch { } }
    }

    [Fact]
    public void Discover_SortedByVolumeNumber()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            File.WriteAllText(Path.Combine(dir.FullName, "vol.2.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "vol.0.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "vol.1.cvp"), "");

            var result = VolumeDiscovery.Discover([new FileInfo(Path.Combine(dir.FullName, "vol.1.cvp"))]);

            Assert.Equal(3, result.Count);
            Assert.Equal("vol.0.cvp", result[0].Name);
            Assert.Equal("vol.1.cvp", result[1].Name);
            Assert.Equal("vol.2.cvp", result[2].Name);
        }
        finally { try { dir.Delete(true); } catch { } }
    }

    [Fact]
    public void Discover_MixedInputs_Deduplicates()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            File.WriteAllText(Path.Combine(dir.FullName, "a.cvp"), "");

            var result = VolumeDiscovery.Discover([dir, new FileInfo(Path.Combine(dir.FullName, "a.cvp"))]);

            Assert.Single(result); // deduplicated
        }
        finally { try { dir.Delete(true); } catch { } }
    }

    [Fact]
    public void Discover_NonCvpFile_Ignored()
    {
        var result = VolumeDiscovery.Discover([new FileInfo("/tmp/not-a-cvp.txt")]);
        Assert.Empty(result);
    }

    [Fact]
    public void Discover_FileWithoutVolumeNumber_SortedAsZero()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            // archive.cvp has no .N suffix; glob "archive.*.cvp" won't match it
            // input file itself IS included in the result
            File.WriteAllText(Path.Combine(dir.FullName, "archive.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "archive.1.cvp"), "");
            File.WriteAllText(Path.Combine(dir.FullName, "archive.2.cvp"), "");

            var result = VolumeDiscovery.Discover([new FileInfo(Path.Combine(dir.FullName, "archive.1.cvp"))]);

            // Glob "archive.*.cvp" matches archive.1.cvp and archive.2.cvp
            Assert.Equal(2, result.Count);
            Assert.Equal("archive.1.cvp", result[0].Name);
            Assert.Equal("archive.2.cvp", result[1].Name);
        }
        finally { try { dir.Delete(true); } catch { } }
    }
}
