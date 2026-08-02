using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib;

namespace CrypVol.Tests;

public class VolumeScannerTests : IDisposable
{
    private readonly string _root;

    public VolumeScannerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"vstest-{Guid.NewGuid()}");
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); }
        catch { }
    }

    [Fact]
    public void ScanPackedVolume_ReturnsFiles()
    {
        var input = Path.Combine(_root, "input");
        var output = Path.Combine(_root, "output");
        Directory.CreateDirectory(input);

        File.WriteAllText(Path.Combine(input, "hello.txt"), "hello scan test");
        File.WriteAllText(Path.Combine(input, "data.json"), "{}");

        // Pack via CLI-like flow
        var cek = RandomNumberGenerator.GetBytes(32);
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "hello.txt")), new FileInfo(Path.Combine(input, "data.json"))
        };
        var (items, volumes) = VolumeAllocator.Allocate(files, input, long.MaxValue);
        var cvpPath = Path.Combine(output, "scan.0.cvp");

        Directory.CreateDirectory(output);
        using (var fs = File.Create(cvpPath))
        {
            // Manually write a simple volume (unencrypted)
            foreach (var item in items)
            {
                var header = new FileEntryHeader
                {
                    FileId = Fnv1AHash64(item.RelativePath),
                    Flags = item.Flags,
                    FragmentIndex = (uint)item.Sequence,
                    SizeOrTotal = item.TotalFileSize
                };
                header.SetFilePath(item.RelativePath);
                fs.Write(header.ToBytes());

                var data = File.ReadAllBytes(Path.Combine(input, item.RelativePath));
                var len = BitConverter.GetBytes(data.Length);
                fs.Write(len);
                fs.Write(data);
            }
        }

        var result = VolumeScanner.Scan([cvpPath]);
        Assert.Equal(2, result.Count);
        Assert.Contains(result.Keys, k => k.EndsWith("hello.txt"));
        Assert.Contains(result.Keys, k => k.EndsWith("data.json"));
    }

    private static ulong Fnv1AHash64(string input)
    {
        const ulong basis = 14695981039346656037ul;
        const ulong prime = 1099511628211ul;
        var hash = basis;
        foreach (var b in Encoding.UTF8.GetBytes(input))
        {
            hash ^= b;
            hash *= prime;
        }

        return hash;
    }
}