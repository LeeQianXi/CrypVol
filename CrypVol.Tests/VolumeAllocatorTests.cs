using CrypVol.Lib;

namespace CrypVol.Tests;

public class VolumeAllocatorTests : IDisposable
{
    private readonly string _root;

    public VolumeAllocatorTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"vatest-{Guid.NewGuid()}");
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); }
        catch { }
    }

    private FileInfo MakeFile(string name, long size)
    {
        var path = Path.Combine(_root, name);
        var dir = Path.GetDirectoryName(path);
        if (dir is not null) Directory.CreateDirectory(dir);
        using var fs = File.Create(path);
        fs.SetLength(size);
        return new FileInfo(path);
    }

    [Fact]
    public void SingleSmallFile_OneVolume()
    {
        var f = MakeFile("a.txt", 100);
        var (items, volumes) = VolumeAllocator.Allocate([f], _root, 1024L * 1024 * 1024);
        Assert.Single(volumes);
        Assert.Single(items);
        Assert.Equal("a.txt", items[0].RelativePath);
        Assert.Equal(0, items[0].VolumeIndex);
        Assert.Equal(100, items[0].Length);
    }

    [Fact]
    public void EmptyFile_OneItem()
    {
        var f = MakeFile("empty.txt", 0);
        var (items, _) = VolumeAllocator.Allocate([f], _root, 1024L * 1024 * 1024);
        Assert.Single(items);
        Assert.Equal(0, items[0].Length);
        Assert.True(items[0].IsFirstFragment);
    }

    [Fact]
    public void FileExceedingVolume_SplitsAcrossVolumes()
    {
        var f = MakeFile("big.bin", 15 * 1024 * 1024); // 15MB
        var (items, volumes) = VolumeAllocator.Allocate([f], _root, 5 * 1024L * 1024); // 5MB volumes

        Assert.True(volumes.Count >= 3, $"expected >=3 volumes, got {volumes.Count}");
        Assert.Equal(volumes.Count, items.Count);
        Assert.Equal(0, items[0].VolumeIndex);
        Assert.Equal(1, items[1].VolumeIndex);
        Assert.Equal(2, items[2].VolumeIndex);
        // Each item is first fragment in its volume
        Assert.All(items, i => Assert.True(i.IsFirstFragment));
        // Total work matches file size
        Assert.Equal(f.Length, items.Sum(i => (long)i.Length));
    }

    [Fact]
    public void MultipleFiles_CorrectVolumeDistribution()
    {
        var f1 = MakeFile("a.bin", 3 * 1024 * 1024);
        var f2 = MakeFile("b.bin", 6 * 1024 * 1024);
        var (items, volumes) = VolumeAllocator.Allocate([f1, f2], _root, 5 * 1024L * 1024);

        Assert.True(volumes.Count >= 2, $"expected >=2 volumes, got {volumes.Count}");
        Assert.Equal(f1.Length + f2.Length, items.Sum(i => (long)i.Length));
    }

    [Fact]
    public void Sequences_PerVolume_StartFromZero()
    {
        var f1 = MakeFile("x.bin", 8 * 1024 * 1024);
        var f2 = MakeFile("y.bin", 2 * 1024 * 1024);
        var (items, _) = VolumeAllocator.Allocate([f1, f2], _root, 5 * 1024L * 1024);

        // Each volume has independent 0-based sequence
        var byVol = items.GroupBy(i => i.VolumeIndex).ToList();
        Assert.True(byVol.Count >= 2, $"expected >=2 volumes, got {byVol.Count}");
        foreach (var group in byVol)
        {
            var sorted = group.OrderBy(i => i.Sequence).ToList();
            Assert.Equal(0, sorted[0].Sequence);
            for (var j = 1; j < sorted.Count; j++)
                Assert.Equal(sorted[j - 1].Sequence + 1, sorted[j].Sequence);
        }
    }

    [Fact]
    public void Subdirectory_PreservesRelativePath()
    {
        var f = MakeFile("sub/dir/file.txt", 500);
        var (items, _) = VolumeAllocator.Allocate([f], _root, 1024L * 1024 * 1024);
        Assert.Equal("sub/dir/file.txt", items[0].RelativePath);
    }

    [Fact]
    public void FileExactlyAtBoundary_HandlesAlignment()
    {
        // 4096 bytes = exactly aligned
        var f = MakeFile("aligned.bin", 4096);
        var (items, _) = VolumeAllocator.Allocate([f], _root, 1024L * 1024 * 1024);
        Assert.Single(items);
        Assert.Equal(4096, items[0].Length);
    }

    [Fact]
    public void FileOneByteOverAlignment_Works()
    {
        var f = MakeFile("odd.bin", 4097);
        var (items, _) = VolumeAllocator.Allocate([f], _root, 1024L * 1024 * 1024);
        Assert.Single(items);
        Assert.Equal(4097, items[0].Length);
    }

    [Fact]
    public void ManySmallFiles_FitInOneVolume()
    {
        var files = new List<FileInfo>();
        for (var i = 0; i < 100; i++)
            files.Add(MakeFile($"file{i}.txt", 100));
        var (items, volumes) = VolumeAllocator.Allocate(files, _root, 1024L * 1024 * 1024);
        Assert.Single(volumes);
        Assert.Equal(100, items.Count);
    }
}