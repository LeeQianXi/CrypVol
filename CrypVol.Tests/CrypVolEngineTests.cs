using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using Xunit;

namespace CrypVol.Tests;

/// <summary>End-to-end integration tests for CrypVolEngine.</summary>
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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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

        var cvkWriter = new CvkWriter(EncryptionMode.Password, "mypassword");
        var credentials = await cvkWriter.WriteCvkAsync(keyDir, "key");

        var engine = new CrypVolEngine();
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

        var cvkReader = new CvkReader(new FileInfo(Path.Combine(keyDir.FullName, "key.cvk")), "mypassword");
        var loaded = await cvkReader.LoadKeyAsync();

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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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
        var data = new byte[20000];
        RandomNumberGenerator.Fill(data);
        MakeFile("big.dat", data);

        var outDir = _workDir.CreateSubdirectory("out");
        var restoreDir = _workDir.CreateSubdirectory("restore");

        var engine = new CrypVolEngine();
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
            VolumeSizeMb = 1
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

        var restored = Path.Combine(restoreDir.FullName, "big.dat");
        Assert.True(File.Exists(restored));
        Assert.Equal(data, await File.ReadAllBytesAsync(restored));
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

        var engine = new CrypVolEngine();
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

        var engine = new CrypVolEngine();
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
        var engine = new CrypVolEngine();

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
        var engine = new CrypVolEngine();

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
        var engine = new CrypVolEngine();
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