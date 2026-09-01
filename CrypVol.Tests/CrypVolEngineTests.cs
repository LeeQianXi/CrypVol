using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;
using Xunit;

namespace CrypVol.Tests;

/// <summary>End-to-end integration tests for CrypVolHelper.</summary>
public class CrypVolEngineTests : IDisposable
{
    private readonly DirectoryInfo _workDir;

    public CrypVolEngineTests()
    {
        _workDir = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cve-{Guid.NewGuid()}"));
        _workDir.Create();
    }

    public void Dispose()
    {
        try { _workDir.Delete(true); }
        catch
        {
            /* best effort */
        }
    }

    private FileInfo MakeFile(string relativePath, byte[] content)
    {
        var full = Path.Combine(_workDir.FullName, relativePath);
        var d = Path.GetDirectoryName(full);
        if (d is not null) Directory.CreateDirectory(d);
        File.WriteAllBytes(full, content);
        return new FileInfo(full);
    }

    private FileInfo MakeFile(string relativePath, string content)
    {
        return MakeFile(relativePath, Encoding.UTF8.GetBytes(content));
    }

    private static List<FileInfo> CvpFiles(PackResult r)
    {
        return r.VolumePaths.Select(p => new FileInfo(p)).ToList();
    }

    // ═══════════════════════════════════════════════════════
    //  Pack → Extract (None mode)
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task PackExtract_NoneMode_SingleFile_RoundTrip()
    {
        MakeFile("hello.txt", "Hello, World!");
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "hello.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);
        Assert.Single(packResult.VolumePaths);
        Assert.True(File.Exists(packResult.VolumePaths[0]));
        var volumeBytes = await File.ReadAllBytesAsync(packResult.VolumePaths[0]);
        Assert.NotEqual(0, volumeBytes[12] & (byte)FileEntryHeaderFlagsEnum.Compressed);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.Equal(1, extractResult.FileCount);

        var restored = Path.Combine(restoreDir.FullName, "hello.txt");
        Assert.True(File.Exists(restored));
        Assert.Equal("Hello, World!", await File.ReadAllTextAsync(restored));
    }

    [Fact]
    public async Task PackExtract_NoneMode_TwoFlatFiles_RoundTrip()
    {
        MakeFile("x.txt", "XContent");
        MakeFile("y.txt", "YContent");
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "x.txt")), new FileInfo(Path.Combine(_workDir.FullName, "y.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.Equal(2, extractResult.FileCount);

        Assert.True(File.Exists(Path.Combine(restoreDir.FullName, "x.txt")));
        Assert.True(File.Exists(Path.Combine(restoreDir.FullName, "y.txt")));
    }

    // ═══════════════════════════════════════════════════════
    //  Pack → Extract (PlainKey mode)
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task PackExtract_PlainKey_SingleFile_RoundTrip()
    {
        MakeFile("secret.txt", "Top Secret Data");
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var credentials = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));

        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "secret.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = credentials
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = credentials
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);

        var restored = Path.Combine(restoreDir.FullName, "secret.txt");
        Assert.True(File.Exists(restored));
        Assert.Equal("Top Secret Data", await File.ReadAllTextAsync(restored));
    }

    [Fact]
    public async Task PackExtract_PlainKey_WrongCek_Fails()
    {
        MakeFile("data.txt", "Sensitive");
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var credentials = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));

        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "data.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = credentials
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var wrongCek = RandomNumberGenerator.GetBytes(32);
        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.PlainKey, wrongCek)
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        // Wrong key can't read encrypted headers
        Assert.False(extractResult.Success);
    }

    // ═══════════════════════════════════════════════════════
    //  Pack → Extract (Password mode)
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task PackExtract_Password_RoundTrip()
    {
        MakeFile("protected.txt", "Password Protected Content");
        var outDir = _workDir.CreateSubdirectory("out");
        var keyDir = _workDir.CreateSubdirectory("keys");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var cvk = CvkDocument.CreateNew(EncryptionMode.Password);
        cvk.Password = "mypassword";
        await cvk.WriteAsync(new FileInfo(Path.Combine(keyDir.FullName, "key.cvk")));
        var credentials = cvk.ToCredentials();

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "protected.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = credentials
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var loadedCvk = await CvkLoader.LoadAsync(
            new FileInfo(Path.Combine(keyDir.FullName, "key.cvk")), "mypassword");
        var loaded = loadedCvk.ToCredentials();

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = loaded
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.Equal("Password Protected Content",
            await File.ReadAllTextAsync(Path.Combine(restoreDir.FullName, "protected.txt")));
    }

    // ═══════════════════════════════════════════════════════
    //  Pack → Browse
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Browse_ReturnsCorrectFileList()
    {
        MakeFile("file1.txt", "AAA");
        MakeFile("sub/file2.txt", "BBB");
        var outDir = _workDir.CreateSubdirectory("out");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "file1.txt")),
                new FileInfo(Path.Combine(_workDir.FullName, "sub/file2.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var browseOpts = new BrowseOptions
        {
            VolumeFiles = CvpFiles(packResult),
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var browseResult = await engine.BrowseAsync(browseOpts);
        Assert.True(browseResult.Success, browseResult.Error);
        Assert.Equal(2, browseResult.Files.Count);
        Assert.Contains(browseResult.Files, f => f.Path == "file1.txt");
        Assert.Contains(browseResult.Files, f => f.Path == "sub/file2.txt");
    }

    // ═══════════════════════════════════════════════════════
    //  Convert (PlainKey → PlainKey)
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Convert_PlainKeyToPlainKey_RoundTrip()
    {
        var data = new byte[5000];
        RandomNumberGenerator.Fill(data);
        MakeFile("data.bin", data);

        var outDir = _workDir.CreateSubdirectory("out");
        var convertDir = _workDir.CreateSubdirectory("convert");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var oldCek = RandomNumberGenerator.GetBytes(32);
        var oldCredentials = new CvkCredentials(EncryptionMode.PlainKey, oldCek);

        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "data.bin"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = oldCredentials
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var newCek = RandomNumberGenerator.GetBytes(32);
        var newCredentials = new CvkCredentials(EncryptionMode.PlainKey, newCek);

        var convertOpts = new ConvertOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = convertDir,
            OutputPrefix = "converted",
            OldCredentials = oldCredentials,
            NewCredentials = newCredentials
        };

        var convertResult = await engine.ConvertAsync(convertOpts);
        Assert.True(convertResult.Success, convertResult.Error);
        Assert.True(convertResult.VolumeCount >= 1);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = convertResult.VolumePaths.Select(p => new FileInfo(p)).ToList(),
            OutputDir = restoreDir,
            Credentials = newCredentials
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.True(File.Exists(Path.Combine(restoreDir.FullName, "data.bin")));
        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(restoreDir.FullName, "data.bin")));
    }

    /// <summary>转换必须保留多块、跨卷文件的条目边界和物理写入顺序。</summary>
    [Fact]
    public async Task Convert_MultiBlockCrossVolumeFile_RoundTrip()
    {
        var data = RandomNumberGenerator.GetBytes(4_500_000);
        MakeFile("large.bin", data);
        var packedDirectory = _workDir.CreateSubdirectory("packed");
        var convertedDirectory = _workDir.CreateSubdirectory("converted");
        var restoredDirectory = _workDir.CreateSubdirectory("restored");
        var engine = new CrypVolHelper();
        var oldCredentials = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));
        var newCredentials = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));

        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "large.bin"))],
            OutputDir = packedDirectory,
            Credentials = oldCredentials,
            EnableCompression = false,
            IntegrityLevel = IntegrityLevel.File,
            ChunkSizeMb = 1,
            VolumeSizeMb = 3
        });
        Assert.True(packResult.Success, packResult.Error);
        Assert.True(packResult.VolumeCount > 1);

        var convertResult = await engine.ConvertAsync(new ConvertOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = convertedDirectory,
            OutputPrefix = "converted",
            OldCredentials = oldCredentials,
            NewCredentials = newCredentials
        });
        Assert.True(convertResult.Success, convertResult.Error);

        var verifyResult = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = convertResult.VolumePaths.Select(path => new FileInfo(path)).ToList(),
            Credentials = newCredentials
        });
        Assert.True(verifyResult.Success, verifyResult.Error);
        Assert.Empty(verifyResult.CorruptedEntries);

        var extractResult = await engine.ExtractAsync(new ExtractOptions
        {
            VolumeFiles = convertResult.VolumePaths.Select(path => new FileInfo(path)).ToList(),
            OutputDir = restoredDirectory,
            Credentials = newCredentials
        });
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(restoredDirectory.FullName, "large.bin")));
    }

    // ═══════════════════════════════════════════════════════
    //  Pack → Extract with include/exclude glob
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Extract_IncludePattern_FiltersFiles()
    {
        MakeFile("keep.txt", "keep");
        MakeFile("skip.log", "skip");
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "keep.txt")),
                new FileInfo(Path.Combine(_workDir.FullName, "skip.log"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>()),
            IncludePattern = "keep.txt"
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.True(File.Exists(Path.Combine(restoreDir.FullName, "keep.txt")));
        Assert.False(File.Exists(Path.Combine(restoreDir.FullName, "skip.log")));
    }

    [Fact]
    public async Task Extract_ExcludePattern_FiltersFiles()
    {
        MakeFile("include.txt", "yes");
        MakeFile("exclude.log", "no");
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "include.txt")),
                new FileInfo(Path.Combine(_workDir.FullName, "exclude.log"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>()),
            ExcludePattern = "*.log"
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.False(File.Exists(Path.Combine(restoreDir.FullName, "exclude.log")));
        Assert.True(File.Exists(Path.Combine(restoreDir.FullName, "include.txt")));
    }

    // ═══════════════════════════════════════════════════════
    //  Multi-volume (split)
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Pack_MultiVolume_LargeFile_SplitsAcrossVolumes()
    {
        // 每卷可容纳多个块，覆盖 CrossTail 不能被前一个 CrossMid 条目头掩盖的场景。
        var data = new byte[7_500_000];
        RandomNumberGenerator.Fill(data);
        MakeFile("big.dat", data);

        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());

        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "big.dat"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = credentials,
            VolumeSizeMb = 3,
            ChunkSizeMb = 1,
            IntegrityLevel = IntegrityLevel.Volume
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);
        Assert.True(packResult.VolumeCount >= 3);
        Assert.All(packResult.VolumePaths, path => Assert.True(VolumeIntegrityFooter.Verify(path)));

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = credentials
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);

        var restored = Path.Combine(restoreDir.FullName, "big.dat");
        Assert.True(File.Exists(restored));
        Assert.Equal(data, await File.ReadAllBytesAsync(restored));
    }

    /// <summary>File 级摘要应发现 CRC 被重新计算后的静默数据篡改。</summary>
    [Fact]
    public async Task Extract_FileIntegrity_DetectsPayloadTamperingWithValidCrc()
    {
        var data = RandomNumberGenerator.GetBytes(1_500_000);
        MakeFile("protected.bin", data);
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());
        var engine = new CrypVolHelper();

        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "protected.bin"))],
            OutputDir = outDir,
            Credentials = credentials,
            ChunkSizeMb = 1,
            EnableCompression = false,
            IntegrityLevel = IntegrityLevel.File
        });
        Assert.True(packResult.Success, packResult.Error);

        var fragment = VolumeScanner.Scan(CvpFiles(packResult)).Files["protected.bin"][0];
        RewriteBlockWithValidCrc(fragment, buffer => buffer[0] ^= 0xFF);

        var verifyResult = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = CvpFiles(packResult),
            Credentials = credentials
        });
        Assert.True(verifyResult.Success, verifyResult.Error);
        Assert.Contains(verifyResult.CorruptedEntries, entry => entry.FilePath == "protected.bin");

        var extractResult = await engine.ExtractAsync(new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = credentials
        });

        Assert.False(extractResult.Success);
        Assert.Contains("SHA-256", extractResult.Error);
    }

    /// <summary>验证引擎应在同一轮运行中汇总多个 File 摘要失败，而非遇到首个失败即停止。</summary>
    [Fact]
    public async Task Verify_FileIntegrity_ReportsAllTamperedFiles()
    {
        MakeFile("first.bin", RandomNumberGenerator.GetBytes(8_192));
        MakeFile("second.bin", RandomNumberGenerator.GetBytes(8_192));
        var outDir = _workDir.CreateSubdirectory("out");
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());
        var engine = new CrypVolHelper();
        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles =
            [
                new FileInfo(Path.Combine(_workDir.FullName, "first.bin")),
                new FileInfo(Path.Combine(_workDir.FullName, "second.bin"))
            ],
            OutputDir = outDir,
            Credentials = credentials,
            EnableCompression = false,
            IntegrityLevel = IntegrityLevel.File
        });
        Assert.True(packResult.Success, packResult.Error);

        var fragments = VolumeScanner.Scan(CvpFiles(packResult)).Files;
        RewriteBlockWithValidCrc(fragments["first.bin"][0], buffer => buffer[0] ^= 0xFF);
        RewriteBlockWithValidCrc(fragments["second.bin"][0], buffer => buffer[0] ^= 0xFF);

        var verifyResult = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = CvpFiles(packResult),
            Credentials = credentials
        });

        Assert.True(verifyResult.Success, verifyResult.Error);
        Assert.Equal(2, verifyResult.CorruptedFiles);
        Assert.Equal(["first.bin", "second.bin"],
            verifyResult.CorruptedEntries.Select(entry => entry.FilePath).OrderBy(path => path));
    }

    /// <summary>混合不同数据格式的卷不能被误当成同一归档并拆分为多条验证流水线。</summary>
    [Fact]
    public async Task Verify_MixedFormatVolumes_ReturnsConfigurationError()
    {
        MakeFile("block.bin", RandomNumberGenerator.GetBytes(1_024));
        MakeFile("file.bin", RandomNumberGenerator.GetBytes(1_024));
        var blockOutDir = _workDir.CreateSubdirectory("block-out");
        var fileOutDir = _workDir.CreateSubdirectory("file-out");
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());
        var engine = new CrypVolHelper();

        var blockPack = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "block.bin"))],
            OutputDir = blockOutDir,
            Credentials = credentials,
            IntegrityLevel = IntegrityLevel.Block
        });
        var filePack = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "file.bin"))],
            OutputDir = fileOutDir,
            Credentials = credentials,
            IntegrityLevel = IntegrityLevel.File
        });
        Assert.True(blockPack.Success, blockPack.Error);
        Assert.True(filePack.Success, filePack.Error);

        var verifyResult = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = [.. CvpFiles(blockPack), .. CvpFiles(filePack)],
            Credentials = credentials
        });

        Assert.False(verifyResult.Success);
        Assert.Contains("配置不一致", verifyResult.Error);
    }

    /// <summary>Block 级 CRC 损坏应被定位；修复副本应重新通过 CRC 校验。</summary>
    [Fact]
    public async Task VerifyAndRepair_BlockIntegrity_DetectsAndRepairsCorruption()
    {
        var data = RandomNumberGenerator.GetBytes(16_384);
        MakeFile("block.bin", data);
        var outDir = _workDir.CreateSubdirectory("out");
        var repairedDir = _workDir.CreateSubdirectory("repaired");
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());
        var engine = new CrypVolHelper();
        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "block.bin"))],
            OutputDir = outDir,
            Credentials = credentials,
            IntegrityLevel = IntegrityLevel.Block
        });
        Assert.True(packResult.Success, packResult.Error);

        var fragment = VolumeScanner.Scan(CvpFiles(packResult)).Files["block.bin"][0];
        RewriteBlockWithValidCrc(fragment, buffer => buffer[0] ^= 0xFF, false);

        var verifyResult = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = CvpFiles(packResult),
            Credentials = credentials
        });
        Assert.True(verifyResult.Success, verifyResult.Error);
        var corruption = Assert.Single(verifyResult.CorruptedEntries);
        Assert.Equal(fragment.CvpFile.FullName, corruption.VolumePath);
        Assert.Equal(fragment.CvpOffset, corruption.CvpOffset);

        var repairResult = await engine.RepairAsync(new RepairOptions
        {
            VolumeFiles = CvpFiles(packResult),
            Credentials = credentials,
            OutputDir = repairedDir
        });
        Assert.True(repairResult.Success, repairResult.Error);
        Assert.Equal(1, repairResult.RepairedBlocks);

        var repairedVerify = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = repairResult.RepairedVolumes.Select(path => new FileInfo(path)).ToList(),
            Credentials = credentials
        });
        Assert.True(repairedVerify.Success, repairedVerify.Error);
        Assert.Empty(repairedVerify.CorruptedEntries);
    }

    /// <summary>Volume 卷尾摘要损坏后，校验和修复都应针对该卷生效。</summary>
    [Fact]
    public async Task VerifyAndRepair_VolumeIntegrity_DetectsAndRewritesFooter()
    {
        MakeFile("volume.bin", RandomNumberGenerator.GetBytes(16_384));
        var outDir = _workDir.CreateSubdirectory("out");
        var repairedDir = _workDir.CreateSubdirectory("repaired");
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());
        var engine = new CrypVolHelper();
        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "volume.bin"))],
            OutputDir = outDir,
            Credentials = credentials,
            IntegrityLevel = IntegrityLevel.Volume
        });
        Assert.True(packResult.Success, packResult.Error);
        var volume = CvpFiles(packResult).Single();
        await using (var stream = new FileStream(volume.FullName, FileMode.Open, FileAccess.ReadWrite))
        {
            stream.Position = stream.Length - 1;
            stream.WriteByte(0);
        }

        var verifyResult = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = [volume],
            Credentials = credentials
        });
        Assert.True(verifyResult.Success, verifyResult.Error);
        Assert.Contains(verifyResult.CorruptedEntries, entry => entry.BlockSize == 0);

        var repairResult = await engine.RepairAsync(new RepairOptions
        {
            VolumeFiles = [volume],
            Credentials = credentials,
            OutputDir = repairedDir
        });
        Assert.True(repairResult.Success, repairResult.Error);
        var repairedVolume = Assert.Single(repairResult.RepairedVolumes);
        Assert.True(VolumeIntegrityFooter.Verify(repairedVolume));
    }

    /// <summary>压缩、加密、多卷和 Volume 完整性组合后仍应完整还原。</summary>
    [Fact]
    public async Task PackExtract_CompressedEncryptedMultiVolume_RoundTrip()
    {
        var data = RandomNumberGenerator.GetBytes(3_500_000);
        MakeFile("combined.bin", data);
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");
        var credentials = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));
        var engine = new CrypVolHelper();

        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "combined.bin"))],
            OutputDir = outDir,
            Credentials = credentials,
            EnableCompression = true,
            CompressionLevel = CompressionLevel.SmallestSize,
            VolumeSizeMb = 2,
            ChunkSizeMb = 1,
            IntegrityLevel = IntegrityLevel.Volume
        });
        Assert.True(packResult.Success, packResult.Error);
        Assert.True(packResult.VolumeCount >= 2);

        var extractResult = await engine.ExtractAsync(new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = credentials
        });
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(restoreDir.FullName, "combined.bin")));
    }

    /// <summary>缺失中间分卷时，不应输出看似完整的文件。</summary>
    [Fact]
    public async Task Extract_MissingIntermediateVolume_FailsWithoutRestoringPartialFile()
    {
        var data = RandomNumberGenerator.GetBytes(5_000_000);
        MakeFile("split.bin", data);
        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");
        var credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>());
        var engine = new CrypVolHelper();
        var packResult = await engine.PackAsync(new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = [new FileInfo(Path.Combine(_workDir.FullName, "split.bin"))],
            OutputDir = outDir,
            Credentials = credentials,
            VolumeSizeMb = 2,
            ChunkSizeMb = 1
        });
        Assert.True(packResult.Success, packResult.Error);
        Assert.True(packResult.VolumeCount >= 3);

        var incompleteVolumes = CvpFiles(packResult)
            .Where((_, index) => index != 1)
            .ToList();
        var extractResult = await engine.ExtractAsync(new ExtractOptions
        {
            VolumeFiles = incompleteVolumes,
            OutputDir = restoreDir,
            Credentials = credentials
        });

        Assert.False(extractResult.Success);
        Assert.False(File.Exists(Path.Combine(restoreDir.FullName, "split.bin")));
    }

    /// <summary>辅助地篡改单个存储块，可选择同步更新 CRC。</summary>
    private static void RewriteBlockWithValidCrc(VolumeScanner.Fragment fragment,
        Action<byte[]> mutate, bool recomputeCrc = true)
    {
        var block = new byte[fragment.BlockSize];
        using var stream = new FileStream(fragment.CvpFile.FullName, FileMode.Open, FileAccess.ReadWrite);
        stream.Position = fragment.CvpOffset;
        Assert.Equal(block.Length, stream.Read(block));
        mutate(block);
        if (recomputeCrc)
            BitConverter.GetBytes(Crc32.Compute(block.AsSpan(0, block.Length - sizeof(uint))))
                .CopyTo(block, block.Length - sizeof(uint));
        stream.Position = fragment.CvpOffset;
        stream.Write(block);
    }

    // ═══════════════════════════════════════════════════════
    //  Pack: binary data roundtrip
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task PackExtract_BinaryData_RoundTrip()
    {
        var binaryData = new byte[8192];
        RandomNumberGenerator.Fill(binaryData);
        MakeFile("binary.bin", binaryData);

        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "binary.bin"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var packResult = await engine.PackAsync(packOpts);
        Assert.True(packResult.Success, packResult.Error);

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = CvpFiles(packResult),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var extractResult = await engine.ExtractAsync(extractOpts);
        Assert.True(extractResult.Success, extractResult.Error);
        Assert.Equal(binaryData, await File.ReadAllBytesAsync(Path.Combine(restoreDir.FullName, "binary.bin")));
    }

    // ═══════════════════════════════════════════════════════
    //  Browse: file properties
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Browse_FileProperties_Correct()
    {
        var content = "Size test";
        MakeFile("size.txt", content);
        var outDir = _workDir.CreateSubdirectory("out");

        var engine = new CrypVolHelper();
        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = new[]
            {
                new FileInfo(Path.Combine(_workDir.FullName, "size.txt"))
            }.ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        await engine.PackAsync(packOpts);
        var cvpFile = new FileInfo(Directory.GetFiles(outDir.FullName, "*.cvp")[0]);

        var browseOpts = new BrowseOptions
        {
            VolumeFiles = new[]
            {
                cvpFile
            }.AsReadOnly(),
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var result = await engine.BrowseAsync(browseOpts);
        Assert.True(result.Success, result.Error);
        var entry = result.Files.Single();
        Assert.Equal("size.txt", entry.Path);
        Assert.Equal(content.Length, entry.Size);
    }

    // ═══════════════════════════════════════════════════════
    //  Error paths
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Pack_NoSourceFiles_ReturnsError()
    {
        var outDir = _workDir.CreateSubdirectory("out");
        var engine = new CrypVolHelper();

        var packOpts = new PackOptions
        {
            SourceFolder = _workDir,
            SourceFiles = Array.Empty<FileInfo>().ToList(),
            OutputDir = outDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var result = await engine.PackAsync(packOpts);
        Assert.False(result.Success);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task Extract_NoVolumeFiles_ReturnsError()
    {
        var restoreDir = _workDir.CreateSubdirectory("restore");
        var engine = new CrypVolHelper();

        var extractOpts = new ExtractOptions
        {
            VolumeFiles = Array.Empty<FileInfo>().AsReadOnly(),
            OutputDir = restoreDir,
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var result = await engine.ExtractAsync(extractOpts);
        Assert.False(result.Success);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task Browse_EmptyVolumeFiles_ReturnsEmptyList()
    {
        var engine = new CrypVolHelper();
        var browseOpts = new BrowseOptions
        {
            VolumeFiles = Array.Empty<FileInfo>().AsReadOnly(),
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        var result = await engine.BrowseAsync(browseOpts);
        Assert.True(result.Success);
        Assert.Empty(result.Files);
    }
}
