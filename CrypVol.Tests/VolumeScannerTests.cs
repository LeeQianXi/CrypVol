using System.Security.Cryptography;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;
using Xunit;

namespace CrypVol.Tests;

public class VolumeScannerTests
{
    private static string TempDir()
    {
        return Path.Combine(Path.GetTempPath(), $"vs-{Guid.NewGuid()}");
    }

    /// <summary>Write a simple plain-header .cvp file with one file entry.</summary>
    private static FileInfo WritePlainCvp(DirectoryInfo dir, string volumeName, string relativePath, byte[] data)
    {
        var path = Path.Combine(dir.FullName, volumeName);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);

        var header = new FileEntryHeader
        {
            FileId = 12345,
            Flags = 0,
            FragmentIndex = 0,
            SizeOrTotal = data.Length
        };
        header.SetFilePath(relativePath);

        var headerBytes = header.ToBytes();
        fs.Write(headerBytes);

        var len = BitConverter.GetBytes(data.Length);
        fs.Write(len);
        fs.Write(data);

        return new FileInfo(path);
    }

    /// <summary>Write an encrypted-header .cvp file with one file entry.</summary>
    private static FileInfo WriteEncryptedCvp(DirectoryInfo dir, string volumeName, string relativePath, byte[] data,
        byte[] cek)
    {
        var path = Path.Combine(dir.FullName, volumeName);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);

        var header = new FileEntryHeader
        {
            FileId = 12345,
            Flags = 0,
            FragmentIndex = 0,
            SizeOrTotal = data.Length
        };
        header.SetFilePath(relativePath);

        var headerBytes = FileEntryHeader.Encrypt(header, cek);
        fs.Write(headerBytes);

        var len = BitConverter.GetBytes(data.Length);
        fs.Write(len);
        fs.Write(data);

        return new FileInfo(path);
    }

    // ── Scan: None mode (plain headers) ──

    [Fact]
    public void Scan_PlainMode_SingleFile_SingleFragment()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var data = new byte[]
            {
                1, 2, 3, 4
            };
            var cvp = WritePlainCvp(dir, "archive.0.cvp", "test.txt", data);

            var result = VolumeScanner.Scan([cvp]).Files;

            Assert.Single(result);
            Assert.True(result.ContainsKey("test.txt"));
            var fragments = result["test.txt"];
            Assert.Single(fragments);
            Assert.Equal(data.Length, fragments[0].BlockSize);
            Assert.Equal(data.Length, fragments[0].TotalFileSize);
            Assert.Equal(0, fragments[0].Flags);
            Assert.True(fragments[0].StartsEntry);
        }
        finally
        {
            try { dir.Delete(true); }
            catch
            {
                // ignored
            }
        }
    }

    [Fact]
    public void Scan_PlainMode_MultipleFiles()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var cvp = WritePlainCvp(dir, "archive.0.cvp", "a.txt", [1, 2, 3]);
            // Append second entry to same file
            using (var fs = new FileStream(cvp.FullName, FileMode.Append, FileAccess.Write))
            {
                var h2 = new FileEntryHeader
                {
                    FileId = 67890,
                    Flags = 0,
                    FragmentIndex = 0,
                    SizeOrTotal = 2
                };
                h2.SetFilePath("b.txt");
                var hb = h2.ToBytes();
                fs.Write(hb);
                var len2 = BitConverter.GetBytes(2);
                fs.Write(len2);
                fs.Write("\t\t"u8);
            }

            var result = VolumeScanner.Scan([cvp]).Files;

            Assert.Equal(2, result.Count);
            Assert.Contains("a.txt", result.Keys);
            Assert.Contains("b.txt", result.Keys);
        }
        finally
        {
            try { dir.Delete(true); }
            catch
            {
                // ignored
            }
        }
    }

    /// <summary>同一条目中的后续块不应重复声明起始头，且扫描结果必须保留物理顺序。</summary>
    [Fact]
    public void Scan_PlainMode_MultipleBlocksInEntry_PreservesEntryBoundaryAndOrder()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "archive.0.cvp");
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                var header = new FileEntryHeader
                {
                    FileId = 1,
                    Flags = 0,
                    FragmentIndex = 0,
                    SizeOrTotal = 3
                };
                header.SetFilePath("joined.bin");
                stream.Write(header.ToBytes());
                stream.Write(BitConverter.GetBytes(2));
                stream.Write([1, 2]);
                stream.Write(BitConverter.GetBytes(1));
                stream.Write([3]);
            }

            var result = VolumeScanner.Scan([new FileInfo(path)]);

            var fragments = result.Files["joined.bin"];
            Assert.Equal(2, fragments.Count);
            Assert.True(fragments[0].StartsEntry);
            Assert.False(fragments[1].StartsEntry);
            Assert.Equal(["joined.bin", "joined.bin"], result.OrderedBlocks.Select(block => block.RelativePath));
            Assert.Equal(fragments, result.OrderedBlocks.Select(block => block.Fragment));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public void Scan_PlainMode_EmptyFile_ReturnsEmpty()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var emptyCvp = new FileInfo(Path.Combine(dir.FullName, "empty.cvp"));
            File.WriteAllText(emptyCvp.FullName, "");

            var result = VolumeScanner.Scan([emptyCvp]).Files;

            Assert.Empty(result);
        }
        finally
        {
            try { dir.Delete(true); }
            catch
            {
                // ignored
            }
        }
    }

    [Fact]
    public void Scan_PlainMode_NoMagic_ReturnsEmpty()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "junk.cvp");
            File.WriteAllBytes(path, new byte[100]); // all zeros, no magic

            var result = VolumeScanner.Scan([new FileInfo(path)]).Files;

            Assert.Empty(result);
        }
        finally
        {
            try { dir.Delete(true); }
            catch
            {
                // ignored
            }
        }
    }

    /// <summary>不可信卷头不得通过父目录跳出解包根目录。</summary>
    [Fact]
    public void Scan_PlainMode_ParentDirectoryPath_ThrowsInvalidDataException()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var cvp = WritePlainCvp(dir, "archive.0.cvp", "../outside.txt", [1]);

            Assert.Throws<InvalidDataException>(() => VolumeScanner.Scan([cvp]));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    /// <summary>长度字段超出卷剩余内容时，扫描器必须在创建片段前拒绝该卷。</summary>
    [Fact]
    public void Scan_PlainMode_TruncatedBlock_ThrowsInvalidDataException()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "truncated.0.cvp");
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                var header = new FileEntryHeader
                {
                    FileId = 1,
                    Flags = 0,
                    FragmentIndex = 0,
                    SizeOrTotal = 100
                };
                header.SetFilePath("truncated.bin");
                stream.Write(header.ToBytes());
                stream.Write(BitConverter.GetBytes(100));
                stream.Write([1]);
            }

            Assert.Throws<InvalidDataException>(() => VolumeScanner.Scan([new FileInfo(path)]));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    /// <summary>输出解析必须拒绝越出根目录的绝对路径与相对路径。</summary>
    [Fact]
    public void VolumePathSafety_ResolveUnderRoot_RejectsEscapingPath()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cvp-output-{Guid.NewGuid()}");

        Assert.Throws<InvalidDataException>(() => VolumePathSafety.ResolveUnderRoot(root, "../outside.txt"));
        Assert.Throws<InvalidDataException>(() => VolumePathSafety.ResolveUnderRoot(root, Path.GetTempPath()));
        Assert.Equal(Path.Combine(root, "safe.txt"), VolumePathSafety.ResolveUnderRoot(root, "safe.txt"));
    }

    // ── Scan: Encrypted mode ──

    [Fact]
    public void Scan_EncryptedMode_SingleFile_RoundTrip()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var cek = RandomNumberGenerator.GetBytes(32);
            var data = new byte[]
            {
                10, 20, 30, 40, 50
            };
            var cvp = WriteEncryptedCvp(dir, "archive.0.cvp", "secret.txt", data, cek);

            var result = VolumeScanner.Scan([cvp], cek).Files;

            Assert.Single(result);
            Assert.True(result.ContainsKey("secret.txt"));
            var fragments = result["secret.txt"];
            Assert.Single(fragments);
            Assert.Equal(data.Length, fragments[0].BlockSize);
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public void Scan_EncryptedMode_WrongCek_ReturnsEmpty()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var cek1 = RandomNumberGenerator.GetBytes(32);
            var cek2 = RandomNumberGenerator.GetBytes(32);
            var data = new byte[]
            {
                1, 2, 3
            };
            var cvp = WriteEncryptedCvp(dir, "archive.0.cvp", "data.txt", data, cek1);

            var result = VolumeScanner.Scan([cvp], cek2).Files;

            // With wrong CEK, header decryption fails and is skipped
            Assert.Empty(result);
        }
        finally
        {
            try { dir.Delete(true); }
            catch
            {
                // ignored
            }
        }
    }

    // ── Fragment record ──

    [Fact]
    public void Fragment_CorrectProperties()
    {
        var cvpFile = new FileInfo("/tmp/test.cvp");
        var fragment = new VolumeScanner.Fragment(cvpFile, 256, 100, 5000, 1, true, 0);

        Assert.Same(cvpFile, fragment.CvpFile);
        Assert.Equal(256, fragment.CvpOffset);
        Assert.Equal(100, fragment.BlockSize);
        Assert.Equal(5000, fragment.TotalFileSize);
        Assert.Equal(1, fragment.Flags);
        Assert.True(fragment.StartsEntry);
    }

    // ── Scan: multiple volumes ──

    [Fact]
    public void Scan_MultipleVolumes_AggregatesFiles()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var cvp1 = WritePlainCvp(dir, "vol.0.cvp", "file1.txt", [1, 2]);
            var cvp2 = WritePlainCvp(dir, "vol.1.cvp", "file2.txt", [3, 4]);

            var result = VolumeScanner.Scan([cvp1, cvp2]).Files;

            Assert.Equal(2, result.Count);
            Assert.Contains("file1.txt", result.Keys);
            Assert.Contains("file2.txt", result.Keys);
        }
        finally
        {
            try { dir.Delete(true); }
            catch
            {
                // ignored
            }
        }
    }

    [Fact]
    public void Scan_NullCek_EncryptedMode_ReturnsEmpty()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var cek = RandomNumberGenerator.GetBytes(32);
            var cvp = WriteEncryptedCvp(dir, "archive.0.cvp", "test.txt", [1, 2, 3], cek);

            // With null CEK, header decryption fails inside catch block, returns empty
            // The null-forgiving cek! in Decrypt causes NRE caught by catch{}
            var result = VolumeScanner.Scan([cvp]).Files;
            Assert.Empty(result);
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public void Scan_WithFilter_SkipsBlockData_CorrectOffsetForNextFile()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "vol.0.cvp");
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                // file_a: 100KB
                var hdrA = new FileEntryHeader
                {
                    FileId = 1,
                    Flags = 0,
                    FragmentIndex = 0,
                    SizeOrTotal = 100_000
                };
                hdrA.SetFilePath("skip_me.bin");
                fs.Write(hdrA.ToBytes());
                fs.Write(BitConverter.GetBytes(100_000));
                fs.Write(new byte[100_000]);

                // file_b: 50 bytes of 0x42
                var hdrB = new FileEntryHeader
                {
                    FileId = 2,
                    Flags = 0,
                    FragmentIndex = 0,
                    SizeOrTotal = 50
                };
                hdrB.SetFilePath("keep_me.bin");
                fs.Write(hdrB.ToBytes());
                fs.Write(BitConverter.GetBytes(50));
                fs.Write(Enumerable.Repeat((byte)0x42, 50).ToArray());
            }

            var filter = new GlobMatcher();
            filter.AddInclude("keep_me.bin");

            var result = VolumeScanner.Scan([new FileInfo(path)], filter: filter);

            Assert.True(result.Files.ContainsKey("keep_me.bin"));
            Assert.False(result.Files.ContainsKey("skip_me.bin"));

            var f = result.Files["keep_me.bin"][0];
            // file_a: 256 + 4 + 100000 = 100260
            // file_b data offset: 100260 + 256 + 4 = 100520
            Assert.Equal(100260 + 256 + 4, f.CvpOffset);
            Assert.Equal(50, f.BlockSize);

            // Read data from cvp to verify it's 0x42, not 0x00 (file_a's data)
            var actual = new byte[50];
            using (var fs = File.OpenRead(path))
            {
                fs.Position = f.CvpOffset;
                fs.ReadExactly(actual);
            }

            Assert.All(actual, b => Assert.Equal((byte)0x42, b));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    // ── FindIncompleteFiles ──

    [Fact]
    public void FindIncompleteFiles_SingleFullFragment_Complete()
    {
        var cvp = new FileInfo("/tmp/test.cvp");
        var fragments = new Dictionary<string, List<VolumeScanner.Fragment>>
        {
            ["file.txt"] = [new VolumeScanner.Fragment(cvp, 260, 100, 100, 0, true, 0)]
        };
        var incomplete = CrypVolHelper.FindIncompleteFiles(fragments);
        Assert.Empty(incomplete);
    }

    [Fact]
    public void FindIncompleteFiles_SingleFragment_NotFull_Incomplete()
    {
        var cvp = new FileInfo("/tmp/test.cvp");
        // CrossHead without CrossTail — incomplete
        var fragments = new Dictionary<string, List<VolumeScanner.Fragment>>
        {
            ["file.txt"] = [new VolumeScanner.Fragment(cvp, 260, 100, 100, 1, true, 0)]
        };
        var incomplete = CrypVolHelper.FindIncompleteFiles(fragments);
        Assert.Single(incomplete);
        Assert.Equal("file.txt", incomplete[0]);
    }

    [Fact]
    public void FindIncompleteFiles_CrossHeadWithCrossTail_Complete()
    {
        var cvp = new FileInfo("/tmp/test.cvp");
        var fragments = new Dictionary<string, List<VolumeScanner.Fragment>>
        {
            ["bigfile.bin"] =
            [
                new VolumeScanner.Fragment(cvp, 260, 1000, 2500, 1, true, 0), // CrossHead, IsFirst
                new VolumeScanner.Fragment(cvp, 1264, 1000, 2500, 2, false, 0), // CrossMid
                new VolumeScanner.Fragment(cvp, 2268, 500, 2500, 3, false, 0) // CrossTail
            ]
        };
        var incomplete = CrypVolHelper.FindIncompleteFiles(fragments);
        Assert.Empty(incomplete);
    }

    [Fact]
    public void FindIncompleteFiles_CrossHeadWithoutCrossTail_Incomplete()
    {
        var cvp = new FileInfo("/tmp/test.cvp");
        // CrossHead + CrossMid but no CrossTail
        var fragments = new Dictionary<string, List<VolumeScanner.Fragment>>
        {
            ["bigfile.bin"] =
            [
                new VolumeScanner.Fragment(cvp, 260, 1000, 2500, 1, true, 0),
                new VolumeScanner.Fragment(cvp, 1264, 1000, 2500, 2, false, 0)
            ]
        };
        var incomplete = CrypVolHelper.FindIncompleteFiles(fragments);
        Assert.Single(incomplete);
    }

    [Fact]
    public void FindIncompleteFiles_MultipleFiles_MixedCompletion()
    {
        var cvp = new FileInfo("/tmp/test.cvp");
        var fragments = new Dictionary<string, List<VolumeScanner.Fragment>>
        {
            ["complete.txt"] = [new VolumeScanner.Fragment(cvp, 260, 100, 100, 0, true, 0)],
            ["incomplete.bin"] = [new VolumeScanner.Fragment(cvp, 520, 50, 200, 1, true, 0)] // CrossHead alone
        };
        var incomplete = CrypVolHelper.FindIncompleteFiles(fragments);
        Assert.Single(incomplete);
        Assert.Equal("incomplete.bin", incomplete[0]);
    }
}
