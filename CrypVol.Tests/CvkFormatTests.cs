using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using Xunit;

namespace CrypVol.Tests;

/// <summary>Direct binary format tests for CVK envelope format.</summary>
public class CvkFormatTests
{
    private static string TempPath()
    {
        return Path.Combine(Path.GetTempPath(), $"fmt-{Guid.NewGuid()}.cvk");
    }

    [Fact]
    public async Task PlainKey_BinaryFormat_RoundTrip_ViaReader()
    {
        var cek = RandomNumberGenerator.GetBytes(32);

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Encoding.ASCII.GetBytes("KEY0"));
        w.Write((byte)1);
        w.Write((byte)0);
        var plPos = ms.Position;
        w.Write(0);
        w.Write(cek);
        var end = ms.Position;
        ms.Position = plPos;
        w.Write(BinaryPrimitives.ReverseEndianness((int)(end - plPos - 4)));

        var binary = ms.ToArray();
        var b64 = Convert.ToBase64String(binary);

        var path = TempPath();
        try
        {
            await File.WriteAllTextAsync(path, b64);
            var loaded = await new CvkReader(new FileInfo(path)).LoadKeyAsync();
            Assert.Equal(cek, loaded.Cek);
            Assert.Equal(EncryptionMode.PlainKey, loaded.EncryptionMode);
        }
        finally
        {
            try { File.Delete(path); }
            catch { }
        }
    }

    [Fact]
    public void PlainKey_RawBinary_ParseWithBinaryReader()
    {
        var cek = RandomNumberGenerator.GetBytes(32);

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Encoding.ASCII.GetBytes("KEY0"));
        w.Write((byte)1);
        w.Write((byte)0);
        var plPos = ms.Position;
        w.Write(0);
        w.Write(cek);
        var end = ms.Position;
        ms.Position = plPos;
        w.Write(BinaryPrimitives.ReverseEndianness((int)(end - plPos - 4)));
        var binary = ms.ToArray();

        // Parse with BinaryReader (same as CvkReader)
        using var rms = new MemoryStream(binary);
        using var r = new BinaryReader(rms);

        Assert.Equal("KEY0", Encoding.ASCII.GetString(r.ReadBytes(4)));
        Assert.Equal(1, r.ReadByte());
        var mode = r.ReadByte();
        Assert.Equal(0, mode);
        var payloadLen = BinaryPrimitives.ReverseEndianness(r.ReadInt32());
        Assert.Equal(32, payloadLen);

        var parsedCek = r.ReadBytes(32);
        Assert.Equal(cek, parsedCek);
    }

    [Fact]
    public async Task PlainKey_CvkWriter_ProducesParseableBinary()
    {
        var writer = new CvkWriter(EncryptionMode.PlainKey);
        var folder = new DirectoryInfo(Path.GetTempPath());
        var prefix = $"fmt-{Guid.NewGuid()}";

        var creds = await writer.WriteCvkAsync(folder, prefix);
        var cvkPath = Path.Combine(folder.FullName, $"{prefix}.cvk");

        try
        {
            Assert.True(File.Exists(cvkPath));
            var b64 = (await File.ReadAllTextAsync(cvkPath)).Trim();
            var data = Convert.FromBase64String(b64);

            // Parse with BinaryReader
            using var rms = new MemoryStream(data);
            using var r = new BinaryReader(rms);

            Assert.Equal("KEY0", Encoding.ASCII.GetString(r.ReadBytes(4)));
            Assert.Equal(1, r.ReadByte());
            var mode = r.ReadByte();
            Assert.Equal(0, mode);
            var payloadLen = BinaryPrimitives.ReverseEndianness(r.ReadInt32());
            Assert.True(payloadLen >= 32);

            var parsedCek = r.ReadBytes(32);
            Assert.Equal(creds.Cek, parsedCek);
        }
        finally
        {
            try { File.Delete(cvkPath); }
            catch { }
        }
    }

    [Fact]
    public async Task PlainKey_FullRoundTrip_NoFileMove()
    {
        var folder = new DirectoryInfo(Path.GetTempPath());
        var prefix = $"rt-{Guid.NewGuid()}";

        var writer = new CvkWriter(EncryptionMode.PlainKey);
        var creds = await writer.WriteCvkAsync(folder, prefix);

        var cvkPath = Path.Combine(folder.FullName, $"{prefix}.cvk");
        Assert.True(File.Exists(cvkPath));

        try
        {
            var reader = new CvkReader(new FileInfo(cvkPath));
            var loaded = await reader.LoadKeyAsync();
            Assert.Equal(creds.Cek, loaded.Cek);
        }
        finally
        {
            try { File.Delete(cvkPath); }
            catch { }
        }
    }
}