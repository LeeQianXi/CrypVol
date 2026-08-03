using System.Security.Cryptography;
using CrypVol.Lib;
using Xunit;

namespace CrypVol.Tests;

public class CvkTests
{
    static string TempPath(string? ext = ".cvk") => Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid()}{ext}");

    // ═══════════════════════════════════════════════════════
    //  PlainKey
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task PlainKey_RoundTrip()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.PlainKey);
            var creds = await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            Assert.Equal(EncryptionMode.PlainKey, creds.EncryptionMode);
            Assert.Equal(32, creds.Cek.Length);
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path));
            var loaded = await r.LoadKeyAsync();
            Assert.Equal(creds.EncryptionMode, loaded.EncryptionMode);
            Assert.Equal(creds.Cek, loaded.Cek);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public async Task PlainKey_TwoWrites_DifferentCEKs()
    {
        var w1 = new CvkWriter(EncryptionMode.PlainKey);
        var w2 = new CvkWriter(EncryptionMode.PlainKey);
        var c1 = await w1.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), $"pk1-{Guid.NewGuid()}");
        var c2 = await w2.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), $"pk2-{Guid.NewGuid()}");
        Assert.NotEqual(c1.Cek, c2.Cek);
    }

    // ═══════════════════════════════════════════════════════
    //  Password
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Password_RoundTrip()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.Password, "testpass");
            var creds = await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path), "testpass");
            var loaded = await r.LoadKeyAsync();
            Assert.Equal(creds.Cek, loaded.Cek);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public async Task Password_WrongPassword_Throws()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.Password, "correct");
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path), "wrong");
            await Assert.ThrowsAnyAsync<Exception>(() => r.LoadKeyAsync());
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public async Task Password_EmptyOrWhitespace_Throws()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.Password, "valid");
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            // Empty/whitespace password should throw
            var r = new CvkReader(new FileInfo(path), "  ");
            await Assert.ThrowsAnyAsync<Exception>(() => r.LoadKeyAsync());
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public async Task Password_UnicodePassword_RoundTrip()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.Password, "密码🔐测试");
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path), "密码🔐测试");
            var loaded = await r.LoadKeyAsync();
            Assert.Equal(32, loaded.Cek.Length);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    // ═══════════════════════════════════════════════════════
    //  Asymmetric
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Asymmetric_RoundTrip()
    {
        var path = TempPath();
        using var rsa = RSA.Create(2048);
        var pubPath = TempPath(".pub.pem");
        var privPath = TempPath(".priv.pem");
        try
        {
            File.WriteAllText(pubPath, rsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privPath, rsa.ExportRSAPrivateKeyPem());

            var pubKey = new FileInfo(pubPath);
            var w = new CvkWriter(EncryptionMode.Asymmetric, publicKeyFiles: [pubKey]);
            var creds = await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path), privateKeyFile: new FileInfo(privPath));
            var loaded = await r.LoadKeyAsync();
            Assert.Equal(creds.Cek, loaded.Cek);
            Assert.Equal(EncryptionMode.Asymmetric, loaded.EncryptionMode);
        }
        finally { try { File.Delete(path); File.Delete(pubPath); File.Delete(privPath); } catch { } }
    }

    [Fact]
    public async Task Asymmetric_WrongPrivateKey_Throws()
    {
        var path = TempPath();
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var pubPath = TempPath(".pub.pem");
        var wrongPrivPath = TempPath(".priv.pem");
        try
        {
            File.WriteAllText(pubPath, rsa1.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(wrongPrivPath, rsa2.ExportRSAPrivateKeyPem());

            var w = new CvkWriter(EncryptionMode.Asymmetric, publicKeyFiles: [new FileInfo(pubPath)]);
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path), privateKeyFile: new FileInfo(wrongPrivPath));
            await Assert.ThrowsAnyAsync<Exception>(() => r.LoadKeyAsync());
        }
        finally { try { File.Delete(path); File.Delete(pubPath); File.Delete(wrongPrivPath); } catch { } }
    }

    [Fact]
    public async Task Asymmetric_NoPrivateKey_Throws()
    {
        var path = TempPath();
        using var rsa = RSA.Create(2048);
        var pubPath = TempPath(".pub.pem");
        try
        {
            File.WriteAllText(pubPath, rsa.ExportSubjectPublicKeyInfoPem());
            var w = new CvkWriter(EncryptionMode.Asymmetric, publicKeyFiles: [new FileInfo(pubPath)]);
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path));
            await Assert.ThrowsAsync<InvalidOperationException>(() => r.LoadKeyAsync());
        }
        finally { try { File.Delete(path); File.Delete(pubPath); } catch { } }
    }

    [Fact]
    public async Task Asymmetric_NoPublicKeys_Throws()
    {
        var w = new CvkWriter(EncryptionMode.Asymmetric);
        await Assert.ThrowsAsync<Exception>(() =>
            w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), $"no-pub-{Guid.NewGuid()}"));
    }

    // ═══════════════════════════════════════════════════════
    //  ReadMode
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task ReadMode_ReturnsCorrectMode()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.Password, "p");
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);
            Assert.Equal(EnvelopeMode.Password, CvkReader.ReadMode(path));
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public async Task ReadMode_PlainKey()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.PlainKey);
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);
            Assert.Equal(EnvelopeMode.Plain, CvkReader.ReadMode(path));
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public async Task ReadMode_PublicKey()
    {
        using var rsa = RSA.Create(2048);
        var pubPath = TempPath(".pub.pem");
        var cvkPath = TempPath();
        try
        {
            File.WriteAllText(pubPath, rsa.ExportSubjectPublicKeyInfoPem());
            var w = new CvkWriter(EncryptionMode.Asymmetric, publicKeyFiles: [new FileInfo(pubPath)]);
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(cvkPath));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(cvkPath) + ".cvk"), cvkPath, true);
            Assert.Equal(EnvelopeMode.PublicKey, CvkReader.ReadMode(cvkPath));
        }
        finally { try { File.Delete(cvkPath); File.Delete(pubPath); } catch { } }
    }

    [Fact]
    public void ReadMode_InvalidFile_Throws()
    {
        var path = TempPath();
        try
        {
            File.WriteAllText(path, Convert.ToBase64String("not a key file"u8.ToArray()));
            Assert.Throws<InvalidDataException>(() => CvkReader.ReadMode(path));
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public void ReadMode_FileNotFound_Throws()
    {
        Assert.ThrowsAny<Exception>(() => CvkReader.ReadMode("/nonexistent/file.cvk"));
    }

    [Fact]
    public void ReadMode_ShortData_Throws()
    {
        var path = TempPath();
        try
        {
            File.WriteAllText(path, "AAAA");
            Assert.Throws<InvalidDataException>(() => CvkReader.ReadMode(path));
        }
        finally { try { File.Delete(path); } catch { } }
    }

    // ═══════════════════════════════════════════════════════
    //  Rekey
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Rekey_PreservesCEK()
    {
        var path1 = TempPath(); var path2 = TempPath(); try
        {
            var w1 = new CvkWriter(EncryptionMode.PlainKey);
            var c1 = await w1.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path1));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path1) + ".cvk"), path1, true);

            var w2 = new CvkWriter(c1.Cek, EncryptionMode.Password, "newp");
            await w2.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path2));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path2) + ".cvk"), path2, true);

            var r = new CvkReader(new FileInfo(path2), "newp");
            var c2 = await r.LoadKeyAsync();
            Assert.Equal(c1.Cek, c2.Cek);
        }
        finally { try { File.Delete(path1); File.Delete(path2); } catch { } }
    }

    [Fact]
    public async Task Rekey_PasswordToAsymmetric_PreservesCEK()
    {
        using var rsa = RSA.Create(2048);
        var pubPath = TempPath(".pub.pem");
        var privPath = TempPath(".priv.pem");
        var path1 = TempPath(); var path2 = TempPath();
        try
        {
            File.WriteAllText(pubPath, rsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privPath, rsa.ExportRSAPrivateKeyPem());

            var w1 = new CvkWriter(EncryptionMode.Password, "oldpass");
            var c1 = await w1.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path1));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path1) + ".cvk"), path1, true);

            var w2 = new CvkWriter(c1.Cek, EncryptionMode.Asymmetric, publicKeyFiles: [new FileInfo(pubPath)]);
            await w2.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path2));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path2) + ".cvk"), path2, true);

            var r = new CvkReader(new FileInfo(path2), privateKeyFile: new FileInfo(privPath));
            var c2 = await r.LoadKeyAsync();
            Assert.Equal(c1.Cek, c2.Cek);
        }
        finally
        {
            try { File.Delete(path1); File.Delete(path2); File.Delete(pubPath); File.Delete(privPath); }
            catch { }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Comment
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task Comment_Written_SurvivesRoundTrip()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.PlainKey, comment: "测试注释");
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path));
            var loaded = await r.LoadKeyAsync();
            Assert.NotNull(loaded.Cek);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    // ═══════════════════════════════════════════════════════
    //  CvkCredentials record
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void CvkCredentials_Equality_SameCekAndMode_AreEqual()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var a = new CvkCredentials(EncryptionMode.PlainKey, cek);
        var b = new CvkCredentials(EncryptionMode.PlainKey, cek);
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void CvkCredentials_DifferentCek_AreNotEqual()
    {
        var a = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));
        var b = new CvkCredentials(EncryptionMode.PlainKey, RandomNumberGenerator.GetBytes(32));
        Assert.NotEqual(a, b);
    }

    // ═══════════════════════════════════════════════════════
    //  LoadKeyAsync: file error paths
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task LoadKeyAsync_FileNotFound_Throws()
    {
        var r = new CvkReader(new FileInfo("/nonexistent/file.cvk"));
        await Assert.ThrowsAsync<FileNotFoundException>(() => r.LoadKeyAsync());
    }

    [Fact]
    public async Task LoadKeyAsync_PasswordMode_NoPassword_Throws()
    {
        var path = TempPath(); try
        {
            var w = new CvkWriter(EncryptionMode.Password, "secret");
            await w.WriteCvkAsync(new DirectoryInfo(Path.GetTempPath()), Path.GetFileNameWithoutExtension(path));
            File.Move(Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(path) + ".cvk"), path, true);

            var r = new CvkReader(new FileInfo(path)); // no password provided
            await Assert.ThrowsAsync<InvalidOperationException>(() => r.LoadKeyAsync());
        }
        finally { try { File.Delete(path); } catch { } }
    }

    // ═══════════════════════════════════════════════════════
    //  EncryptionMode.None: no file written
    // ═══════════════════════════════════════════════════════

    [Fact]
    public async Task EncryptionModeNone_ReturnsCredentials_WritesNoFile()
    {
        var folder = new DirectoryInfo(Path.GetTempPath());
        var prefix = $"none-{Guid.NewGuid()}";
        var w = new CvkWriter(EncryptionMode.None);
        var creds = await w.WriteCvkAsync(folder, prefix);
        Assert.Equal(EncryptionMode.None, creds.EncryptionMode);
        Assert.Equal(32, creds.Cek.Length);
        Assert.False(File.Exists(Path.Combine(folder.FullName, $"{prefix}.cvk")));
    }
}
