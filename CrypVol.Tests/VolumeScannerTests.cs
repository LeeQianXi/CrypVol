using System.Security.Cryptography;
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
            Assert.True(fragments[0].IsFirst);
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
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
                fs.Write(new byte[]
                {
                    9, 9
                });
            }

            var result = VolumeScanner.Scan([cvp]).Files;

            Assert.Equal(2, result.Count);
            Assert.Contains("a.txt", result.Keys);
            Assert.Contains("b.txt", result.Keys);
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
            catch { }
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
            catch { }
        }
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
            catch { }
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
        Assert.True(fragment.IsFirst);
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
            catch { }
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
}