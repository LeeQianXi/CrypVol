using CrypVol.Lib;
using Xunit;

namespace CrypVol.Tests;

public class VolumeAllocatorTests
{
    private static string TempDir() => Path.Combine(Path.GetTempPath(), $"va-{Guid.NewGuid()}");

    private static FileInfo MakeFile(DirectoryInfo dir, string name, long size)
    {
        var path = Path.Combine(dir.FullName, name);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        fs.SetLength(size);
        return new FileInfo(path);
    }

    [Fact]
    public void Allocate_SingleSmallFile_FitsInOneVolume()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "test.txt", 100);

        var (items, volumes) = VolumeAllocator.Allocate([file], tmp.Dir, 1024 * 1024);

        Assert.Single(items);
        Assert.Single(volumes);
        Assert.Equal(0, volumes[0].Index);
        var item = items[0];
        Assert.Equal("test.txt", item.RelativePath);
        Assert.Equal(100, item.Length);
        Assert.Equal(0, item.Flags); // Full
    }

    [Fact]
    public void Allocate_EmptyFile_CreatesHeaderOnlyItem()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "empty.txt", 0);

        var (items, volumes) = VolumeAllocator.Allocate([file], tmp.Dir, 1024 * 1024);

        Assert.Single(items);
        Assert.Equal(0, items[0].Length);
        Assert.Equal(0, items[0].TotalFileSize);
        Assert.Equal(0, items[0].Flags);
    }

    [Fact]
    public void Allocate_MultipleFiles_SameVolume()
    {
        using var tmp = new TempDirScope();
        var files = new[]
        {
            MakeFile(tmp.Dir, "a.txt", 100),
            MakeFile(tmp.Dir, "b.txt", 200),
            MakeFile(tmp.Dir, "c.txt", 300)
        };

        var (items, volumes) = VolumeAllocator.Allocate(files, tmp.Dir, 1024 * 1024);

        Assert.Single(volumes);
        Assert.Equal(3, items.Count);
        Assert.All(items, item => Assert.Equal(0, item.VolumeIndex));
    }

    [Fact]
    public void Allocate_FileLargerThanVolume_SplitsAcrossVolumes()
    {
        using var tmp = new TempDirScope();
        // Use small volume capacity to force splitting
        var file = MakeFile(tmp.Dir, "big.bin", 10000);

        var (items, volumes) = VolumeAllocator.Allocate([file], tmp.Dir, volumeCapacity: 4096 + 284, headerSize: 284);

        // File should be split across multiple volumes
        Assert.True(volumes.Count >= 3);
        Assert.True(items.Count >= 3);

        // First fragment should be CrossHead (flags=1)
        Assert.Equal(1, items[0].Flags);
        // Last fragment should be CrossTail (flags=3)
        var last = items[^1];
        Assert.Equal(3, last.Flags);

        // Total physical lengths should cover the file
        var totalCovered = items.Sum(i => (long)i.Length);
        Assert.True(totalCovered >= 10000);
    }

    [Fact]
    public void Allocate_SequenceNumbers_Incrementing()
    {
        using var tmp = new TempDirScope();
        var files = new[]
        {
            MakeFile(tmp.Dir, "a.txt", 100),
            MakeFile(tmp.Dir, "b.txt", 200)
        };

        var (items, _) = VolumeAllocator.Allocate(files, tmp.Dir, 1024 * 1024);

        // Sequences should be 0 and 1 within the same volume
        Assert.Equal(0, items[0].Sequence);
        Assert.Equal(1, items[1].Sequence);
    }

    [Fact]
    public void Allocate_LongPath_Skipped()
    {
        using var tmp = new TempDirScope();
        // Create a deeply nested path that exceeds maxPathLen (487) via directory depth,
        // not single-filename length, since ext4 limits filenames to 255 bytes.
        var deepDir = tmp.Dir;
        for (var i = 0; i < 10; i++)
            deepDir = deepDir.CreateSubdirectory(new string('d', 48));
        // Now relative path = d{48}/d{48}/.../d{48}/file.txt = 10*49 + 8 ≈ 498 chars
        var file = MakeFile(deepDir, "file.txt", 100);

        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, 1024 * 1024);

        // Path > maxPathLen (231+256=487) should be skipped
        Assert.Empty(items);
    }

    [Fact]
    public void Allocate_ShortPath_Included()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "short.txt", 50);

        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, 1024 * 1024);

        Assert.Single(items);
    }

    [Fact]
    public void Allocate_RelativePath_IsRelative()
    {
        using var tmp = new TempDirScope();
        var subDir = tmp.Dir.CreateSubdirectory("sub");
        var file = MakeFile(subDir, "nested.txt", 100);

        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, 1024 * 1024);

        Assert.Single(items);
        Assert.Equal(Path.Combine("sub", "nested.txt"), items[0].RelativePath);
    }

    [Fact]
    public void Allocate_SourceOffset_TracksCorrectly()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "split.bin", 20000);
        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, volumeCapacity: 4096 + 284, headerSize: 284);

        // First item should start at offset 0
        Assert.Equal(0, items[0].SourceOffset);

        // Subsequent items should have increasing offsets
        for (var i = 1; i < items.Count; i++)
            Assert.True(items[i].SourceOffset > items[i - 1].SourceOffset);
    }

    [Fact]
    public void Allocate_TotalFileSize_PreservedInAllFragments()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "multi.bin", 20000);
        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, volumeCapacity: 4096 + 284, headerSize: 284);

        Assert.All(items, item => Assert.Equal(20000, item.TotalFileSize));
    }

    [Fact]
    public void Allocate_EmptyFiles_NoItems()
    {
        using var tmp = new TempDirScope();
        var (items, volumes) = VolumeAllocator.Allocate([], tmp.Dir, 1024 * 1024);
        Assert.Empty(items);
        Assert.Empty(volumes);
    }

    [Fact]
    public void Allocate_Flags_CrossMidHasCorrectValue()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "big.dat", 50000);
        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, volumeCapacity: 4096 + 284, headerSize: 284);

        // Should have at least one CrossMid (flags=2) fragment
        Assert.Contains(items, i => i.Flags == 2);
    }

    [Fact]
    public void Allocate_IsFirstFragment_AlwaysTrue()
    {
        using var tmp = new TempDirScope();
        var file = MakeFile(tmp.Dir, "test.bin", 20000);
        var (items, _) = VolumeAllocator.Allocate([file], tmp.Dir, volumeCapacity: 4096 + 284, headerSize: 284);

        // Current implementation sets IsFirstFragment=true on ALL fragments
        Assert.All(items, item => Assert.True(item.IsFirstFragment));
    }
}

/// <summary>Helper to clean up temp directories after tests</summary>
public sealed class TempDirScope : IDisposable
{
    public DirectoryInfo Dir { get; }

    public TempDirScope()
    {
        Dir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"va-{Guid.NewGuid()}"));
        Dir.Create();
    }

    public void Dispose()
    {
        try { Dir.Delete(true); }
        catch { /* best effort */ }
    }
}
