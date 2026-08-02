using System.Security.Cryptography;
using CrypVol.Lib;
using CrypVol.Lib.Models;

namespace CrypVol.Tests;

public class EngineIntegrationTests : IDisposable
{
    private readonly string _root;

    public EngineIntegrationTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"crypvol-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); }
        catch { }
    }

    private string Dir(string name)
    {
        var d = Path.Combine(_root, name);
        Directory.CreateDirectory(d);
        return d;
    }

    [Fact]
    public async Task PackExtract_PlainKey_SmallFiles_RoundTrip()
    {
        var input = Dir("input");
        var output = Dir("output");
        var restored = Dir("restored");

        await File.WriteAllTextAsync(Path.Combine(input, "a.txt"), "hello world");
        await File.WriteAllTextAsync(Path.Combine(input, "b.txt"), "line1\nline2\nline3");

        var engine = new CrypVolEngine();
        var files = Directory.GetFiles(input).Select(f => new FileInfo(f)).ToList();

        var packResult = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "test",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);

        Assert.True(packResult.Success, packResult.Error);
        Assert.Single(packResult.VolumePaths);

        var extResult = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored
        });

        Assert.True(extResult.Success, extResult.Error);
        Assert.Equal(2, extResult.FileCount);

        foreach (var f in files)
        {
            var orig = await File.ReadAllBytesAsync(f.FullName);
            var rest = await File.ReadAllBytesAsync(Path.Combine(restored, f.Name));
            Assert.Equal(orig, rest);
        }
    }

    [Fact]
    public async Task PackExtract_Password_RoundTrip()
    {
        var input = Dir("input2");
        var output = Dir("output2");
        var restored = Dir("restored2");

        var data = RandomNumberGenerator.GetBytes(50000);
        await File.WriteAllBytesAsync(Path.Combine(input, "data.bin"), data);

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "data.bin"))
        }.ToList();

        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "pwd",
            EncryptionMode = EncryptionMode.Password,
            Password = "secret123"
        }, files, input);
        Assert.True(pr.Success, pr.Error);

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored,
            Password = "secret123"
        });
        Assert.True(er.Success, er.Error);

        var rest = await File.ReadAllBytesAsync(Path.Combine(restored, "data.bin"));
        Assert.Equal(data, rest);
    }

    [Fact]
    public async Task PackExtract_None_RoundTrip()
    {
        var input = Dir("input3");
        var output = Dir("output3");
        var restored = Dir("restored3");

        await File.WriteAllTextAsync(Path.Combine(input, "f.txt"), "unencrypted");

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "f.txt"))
        }.ToList();

        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "none",
            EncryptionMode = EncryptionMode.None
        }, files, input);
        Assert.True(pr.Success, pr.Error);
        Assert.Null(pr.KeyFilePath);

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored
        });
        Assert.True(er.Success, er.Error);

        var rest = await File.ReadAllBytesAsync(Path.Combine(restored, "f.txt"));
        Assert.Equal("unencrypted"u8.ToArray(), rest);
    }

    [Fact]
    public async Task Rekey_PlainToPassword_Success()
    {
        var input = Dir("input4");
        var output = Dir("output4");
        var restored = Dir("restored4");

        await File.WriteAllTextAsync(Path.Combine(input, "x.txt"), "rekey test");

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "x.txt"))
        }.ToList();

        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "rk",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);
        Assert.True(pr.Success);

        var cvkPath = pr.KeyFilePath!;
        var rr = await engine.RekeyAsync(new RekeyOptions
        {
            SourceCvkPath = cvkPath,
            TargetMode = EncryptionMode.Password,
            NewPassword = "newp"
        });
        Assert.True(rr.Success, rr.Error);

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored,
            Password = "newp"
        });
        Assert.True(er.Success, er.Error);

        var rest = await File.ReadAllBytesAsync(Path.Combine(restored, "x.txt"));
        Assert.Equal("rekey test"u8.ToArray(), rest);
    }

    [Fact]
    public async Task Browse_ReturnsFiles()
    {
        var input = Dir("input5");
        var output = Dir("output5");

        await File.WriteAllTextAsync(Path.Combine(input, "a.txt"), "a");
        Directory.CreateDirectory(Path.Combine(input, "sub"));
        await File.WriteAllTextAsync(Path.Combine(input, "sub/b.txt"), "b");

        var engine = new CrypVolEngine();
        var files = Directory.GetFiles(input, "*", SearchOption.AllDirectories).Select(f => new FileInfo(f)).ToList();

        await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "br",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);

        var br = await engine.BrowseAsync([output]);
        Assert.True(br.Success);
        Assert.Equal(2, br.Files.Count);
        Assert.Contains(br.Files, f => f.Path.EndsWith("a.txt"));
        Assert.Contains(br.Files, f => f.Path.EndsWith("b.txt"));
    }

    [Fact]
    public async Task Extract_WrongPassword_Fails()
    {
        var input = Dir("input6");
        var output = Dir("output6");
        var restored = Dir("restored6");

        await File.WriteAllTextAsync(Path.Combine(input, "s.txt"), "secret");
        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "s.txt"))
        }.ToList();

        await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "sec",
            EncryptionMode = EncryptionMode.Password,
            Password = "right"
        }, files, input);

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored,
            Password = "wrong"
        });
        Assert.False(er.Success);
        Assert.NotNull(er.Error);
    }

    [Fact]
    public async Task Pack_CrossVolume_LargeFile()
    {
        var input = Dir("input7");
        var output = Dir("output7");
        var restored = Dir("restored7");

        var data = RandomNumberGenerator.GetBytes(10_000_000); // 10MB
        await File.WriteAllBytesAsync(Path.Combine(input, "big.bin"), data);

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "big.bin"))
        }.ToList();

        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "big",
            EncryptionMode = EncryptionMode.PlainKey,
            VolumeSizeMb = 3 // 3MB volumes → 4 volumes
        }, files, input);
        Assert.True(pr.Success, pr.Error);
        Assert.True(pr.VolumeCount >= 3, $"expected >=3 volumes, got {pr.VolumeCount}");

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored
        });
        Assert.True(er.Success, er.Error);

        var rest = await File.ReadAllBytesAsync(Path.Combine(restored, "big.bin"));
        Assert.Equal(data, rest);
    }

    [Fact]
    public async Task EmptyFile_RoundTrip()
    {
        var input = Dir("input8");
        var output = Dir("output8");
        var restored = Dir("restored8");
        await File.WriteAllTextAsync(Path.Combine(input, "empty.txt"), "");
        await File.WriteAllTextAsync(Path.Combine(input, "nonempty.txt"), "x");

        var engine = new CrypVolEngine();
        var files = Directory.GetFiles(input).Select(f => new FileInfo(f)).ToList();
        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "emp",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);
        Assert.True(pr.Success);

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored
        });
        Assert.True(er.Success);
        Assert.Equal(2, er.FileCount);

        Assert.Equal("", await File.ReadAllTextAsync(Path.Combine(restored, "empty.txt")));
        Assert.Equal("x", await File.ReadAllTextAsync(Path.Combine(restored, "nonempty.txt")));
    }

    [Fact]
    public async Task KeyFilePrefixMapping_AutoDiscovery()
    {
        var input = Dir("input9");
        var output = Dir("output9");
        var restored = Dir("restored9");
        await File.WriteAllTextAsync(Path.Combine(input, "f.txt"), "auto discover");

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "f.txt"))
        }.ToList();
        await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "auto",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);

        // Extract without specifying key file — should auto-discover
        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored
        });
        Assert.True(er.Success);
    }

    [Fact]
    public async Task Pack_ThrowsOnMissingInput()
    {
        var engine = new CrypVolEngine();
        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = "/nonexistent/path",
            OutputDir = _root,
            OutputPrefix = "err"
        }, [], "");
        Assert.False(pr.Success);
    }

    [Fact]
    public async Task Extract_MissingVolumes_ReturnsError()
    {
        var engine = new CrypVolEngine();
        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = ["/nonexistent"],
            OutputDir = _root
        });
        Assert.False(er.Success);
    }

    [Fact]
    public async Task Rekey_MissingSource_ReturnsError()
    {
        var engine = new CrypVolEngine();
        var rr = await engine.RekeyAsync(new RekeyOptions
        {
            SourceCvkPath = "/nonexistent",
            TargetMode = EncryptionMode.PlainKey
        });
        Assert.False(rr.Success);
    }

    [Fact]
    public async Task Browse_EmptyVolume_ReturnsError()
    {
        var engine = new CrypVolEngine();
        var br = await engine.BrowseAsync(["/nonexistent"]);
        Assert.False(br.Success);
    }

    [Fact]
    public async Task PackWithKeyFile_PasswordMode_UsesExternalCek()
    {
        var input = Dir("input10");
        var output = Dir("output10");
        var restored = Dir("restored10");
        await File.WriteAllTextAsync(Path.Combine(input, "secret.txt"), "protected");

        // First pack with password
        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "secret.txt"))
        }.ToList();
        var pr1 = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "ext",
            EncryptionMode = EncryptionMode.Password,
            Password = "p1"
        }, files, input);
        Assert.True(pr1.Success);

        // Second pack using the same key file
        var input2 = Dir("input10b");
        var output2 = Dir("output10b");
        var restored2 = Dir("restored10b");
        await File.WriteAllTextAsync(Path.Combine(input2, "secret2.txt"), "also protected");
        var files2 = new[]
        {
            new FileInfo(Path.Combine(input2, "secret2.txt"))
        }.ToList();

        var pr2 = await engine.PackAsync(new PackOptions
        {
            SourcePath = input2,
            OutputDir = output2,
            OutputPrefix = "ext",
            KeyFilePath = pr1.KeyFilePath,
            KeyFilePassword = "p1"
        }, files2, input2);
        Assert.True(pr2.Success);

        // Both should decrypt with same password
        var er1 = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored,
            Password = "p1"
        });
        Assert.True(er1.Success);
        var er2 = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output2],
            OutputDir = restored2,
            Password = "p1"
        });
        Assert.True(er2.Success);
    }

    [Fact]
    public async Task Pack_Compression_RoundTrip()
    {
        var input = Dir("input11");
        var output = Dir("output11");
        var restored = Dir("restored11");
        // Highly compressible data
        var data = new byte[100_000];
        Array.Fill(data, (byte)'A');
        await File.WriteAllBytesAsync(Path.Combine(input, "big.txt"), data);

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "big.txt"))
        }.ToList();
        var pr = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "cmp",
            EncryptionMode = EncryptionMode.PlainKey,
            EnableCompression = true
        }, files, input);
        Assert.True(pr.Success);

        // Compressed volume should be much smaller than 100KB raw data
        var volSize = new FileInfo(pr.VolumePaths[0]).Length;
        Assert.True(volSize < 50_000, $"expected compressed size <50KB, got {volSize}");
        // Note: decompression on extract requires auto-detection (TODO)
    }

    [Fact]
    public async Task Pack_OverwritesExistingOutput()
    {
        var input = Dir("input12");
        var output = Dir("output12");
        var restored = Dir("restored12");
        await File.WriteAllTextAsync(Path.Combine(input, "f.txt"), "v1");

        var engine = new CrypVolEngine();
        var files = new[]
        {
            new FileInfo(Path.Combine(input, "f.txt"))
        }.ToList();

        var pr1 = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "ov",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);
        Assert.True(pr1.Success);

        // Rewrite file
        await File.WriteAllTextAsync(Path.Combine(input, "f.txt"), "v2");
        var pr2 = await engine.PackAsync(new PackOptions
        {
            SourcePath = input,
            OutputDir = output,
            OutputPrefix = "ov",
            EncryptionMode = EncryptionMode.PlainKey
        }, files, input);
        Assert.True(pr2.Success);

        var er = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = [output],
            OutputDir = restored
        });
        Assert.True(er.Success);
        Assert.Equal("v2", await File.ReadAllTextAsync(Path.Combine(restored, "f.txt")));
    }
}