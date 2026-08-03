using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib;
using CrypVol.Lib.Transforms;
using CrypVol.Lib.Volume;
using Xunit;

namespace CrypVol.Tests;

public class FileEntryHeaderIntegrityTests
{
    [Fact]
    public void GetIntegrityLevel_Default_IsNone()
    {
        var hdr = new FileEntryHeader();
        Assert.Equal(IntegrityLevel.None, hdr.GetIntegrityLevel());
    }

    [Fact]
    public void SetGet_RoundTrip_AllValues()
    {
        foreach (var level in Enum.GetValues<IntegrityLevel>())
        {
            var hdr = new FileEntryHeader();
            hdr.SetIntegrityLevel(level);
            Assert.Equal(level, hdr.GetIntegrityLevel());
        }
    }

    [Fact]
    public void SetIntegrityLevel_PreservesFragmentFlags()
    {
        var hdr = new FileEntryHeader
        {
            Flags = 3
        }; // CrossTail
        hdr.SetIntegrityLevel(IntegrityLevel.Block);
        Assert.Equal(3, hdr.Flags & 3); // fragment flags preserved
        Assert.Equal(IntegrityLevel.Block, hdr.GetIntegrityLevel());
    }

    [Fact]
    public void SetIntegrityLevel_PreservesExtendedHeaderFlag()
    {
        var hdr = new FileEntryHeader
        {
            Flags = 4
        }; // HasExtendedHeader
        hdr.SetIntegrityLevel(IntegrityLevel.Volume);
        Assert.Equal(4, hdr.Flags & 4); // HasExtendedHeader preserved
        Assert.Equal(IntegrityLevel.Volume, hdr.GetIntegrityLevel());
    }

    [Fact]
    public void SetIntegrityLevel_None_ClearsBits()
    {
        var hdr = new FileEntryHeader();
        hdr.SetIntegrityLevel(IntegrityLevel.Volume);
        Assert.Equal(IntegrityLevel.Volume, hdr.GetIntegrityLevel());
        hdr.SetIntegrityLevel(IntegrityLevel.None);
        Assert.Equal(IntegrityLevel.None, hdr.GetIntegrityLevel());
    }

    [Fact]
    public void ToBytes_PreservesIntegrityLevel()
    {
        var hdr = new FileEntryHeader();
        hdr.SetIntegrityLevel(IntegrityLevel.File);
        var bytes = hdr.ToBytes();
        Assert.Equal(IntegrityLevel.File, (IntegrityLevel)(bytes[12] >> 3 & 3));
    }

    [Fact]
    public void IntegrityBits_DontOverlap_FragmentBits()
    {
        // Verify bits 3-4 (IntegrityLevel) don't overlap bits 0-1 (fragment type)
        var hdr = new FileEntryHeader();
        hdr.SetIntegrityLevel(IntegrityLevel.Volume); // bits 3-4 = 11
        Assert.Equal(0, hdr.Flags & 3); // fragment type still Full
        hdr.Flags |= 2; // set CrossMid
        Assert.Equal(IntegrityLevel.Volume, hdr.GetIntegrityLevel());
        Assert.Equal(2, hdr.Flags & 3);
    }
}

public class PackTransformIntegrityTests
{
    [Fact]
    public void None_NoCrc32Appended()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var t = new PackTransform(cek, false, 6);
        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var output = t.Transform(input, 100, out var len);
            // No CRC32: len = 12 + 100 + 16 = 128
            Assert.Equal(128, len);
            ArrayPool<byte>.Shared.Return(output);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Block_AppendsCrc32()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var t = new PackTransform(cek, false, 6, IntegrityLevel.Block);
        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var output = t.Transform(input, 100, out var len);
            // With CRC32: len = 12 + 100 + 16 + 4 = 132
            Assert.Equal(132, len);
            ArrayPool<byte>.Shared.Return(output);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void File_SameAsBlock_Crc32Appended()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var t = new PackTransform(cek, false, 6, IntegrityLevel.File);
        var input = ArrayPool<byte>.Shared.Rent(50);
        try
        {
            var output = t.Transform(input, 50, out var len);
            Assert.Equal(12 + 50 + 16 + 4, len);
            ArrayPool<byte>.Shared.Return(output);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Volume_SameAsBlock_Crc32Appended()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var t = new PackTransform(cek, false, 6, IntegrityLevel.Volume);
        var input = ArrayPool<byte>.Shared.Rent(50);
        try
        {
            var output = t.Transform(input, 50, out var len);
            Assert.Equal(12 + 50 + 16 + 4, len);
            ArrayPool<byte>.Shared.Return(output);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }
}

public class ExtractTransformIntegrityTests
{
    [Fact]
    public void None_DecryptsNormally()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6);
        var extract = new ExtractTransform(cek, false);

        var input = ArrayPool<byte>.Shared.Rent(200);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 200, out var encLen);
            var dec = extract.Transform(enc, encLen, out var decLen);
            Assert.Equal(200, decLen);
            Assert.True(input.AsSpan(0, 200).SequenceEqual(dec.AsSpan(0, 200)));
            ArrayPool<byte>.Shared.Return(dec);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Block_RoundTrip_VerifiesCrc32()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6, IntegrityLevel.Block);
        var extract = new ExtractTransform(cek, false, IntegrityLevel.Block);

        var input = ArrayPool<byte>.Shared.Rent(200);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 200, out var encLen);
            Assert.Equal(12 + 200 + 16 + 4, encLen);
            var dec = extract.Transform(enc, encLen, out var decLen);
            Assert.Equal(200, decLen);
            Assert.True(input.AsSpan(0, 200).SequenceEqual(dec.AsSpan(0, 200)));
            ArrayPool<byte>.Shared.Return(dec);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Block_CorruptedCrc32_Throws()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6, IntegrityLevel.Block);
        var extract = new ExtractTransform(cek, false, IntegrityLevel.Block);

        var input = ArrayPool<byte>.Shared.Rent(200);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 200, out var encLen);
            // Corrupt a byte in the ciphertext
            enc[50] ^= 0xFF;
            Assert.Throws<InvalidDataException>(() => extract.Transform(enc, encLen, out _));
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Block_TamperedCrc32_Throws()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6, IntegrityLevel.Block);
        var extract = new ExtractTransform(cek, false, IntegrityLevel.Block);

        var input = ArrayPool<byte>.Shared.Rent(200);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 200, out var encLen);
            // Tamper with the CRC32 bytes at the end
            enc[encLen - 1] ^= 0xFF;
            Assert.Throws<InvalidDataException>(() => extract.Transform(enc, encLen, out _));
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Block_WithCompression_RoundTrip()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, true, 6, IntegrityLevel.Block);
        var extract = new ExtractTransform(cek, true, IntegrityLevel.Block);

        var input = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 4096, out var encLen);
            var dec = extract.Transform(enc, encLen, out var decLen);
            Assert.Equal(4096, decLen);
            Assert.True(input.AsSpan(0, 4096).SequenceEqual(dec.AsSpan(0, 4096)));
            ArrayPool<byte>.Shared.Return(dec);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }
}

public class ConvertTransformIntegrityTests
{
    [Fact]
    public void Block_PreservesCrc32_AfterRekey()
    {
        var oldCek = RandomNumberGenerator.GetBytes(32);
        var newCek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(oldCek, false, 6, IntegrityLevel.Block);
        var convert = new ConvertTransform(oldCek, newCek, IntegrityLevel.Block);
        var extract = new ExtractTransform(newCek, false, IntegrityLevel.Block);

        var input = ArrayPool<byte>.Shared.Rent(300);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 300, out var encLen);
            var conv = convert.Transform(enc, encLen, out var convLen);
            var dec = extract.Transform(conv, convLen, out var decLen);
            Assert.Equal(300, decLen);
            Assert.True(input.AsSpan(0, 300).SequenceEqual(dec.AsSpan(0, 300)));
            ArrayPool<byte>.Shared.Return(dec);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void None_NoCrc32_Works()
    {
        var oldCek = RandomNumberGenerator.GetBytes(32);
        var newCek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(oldCek, false, 6);
        var convert = new ConvertTransform(oldCek, newCek);
        var extract = new ExtractTransform(newCek, false);

        var input = ArrayPool<byte>.Shared.Rent(200);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 200, out var encLen);
            var conv = convert.Transform(enc, encLen, out var convLen);
            var dec = extract.Transform(conv, convLen, out var decLen);
            Assert.Equal(200, decLen);
            Assert.True(input.AsSpan(0, 200).SequenceEqual(dec.AsSpan(0, 200)));
            ArrayPool<byte>.Shared.Return(dec);
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }

    [Fact]
    public void Block_Corrupted_Throws()
    {
        var oldCek = RandomNumberGenerator.GetBytes(32);
        var newCek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(oldCek, false, 6, IntegrityLevel.Block);
        var convert = new ConvertTransform(oldCek, newCek, IntegrityLevel.Block);

        var input = ArrayPool<byte>.Shared.Rent(200);
        try
        {
            RandomNumberGenerator.Fill(input);
            var enc = pack.Transform(input, 200, out var encLen);
            enc[60] ^= 0xFF; // corrupt
            Assert.Throws<InvalidDataException>(() => convert.Transform(enc, encLen, out _));
        }
        finally { ArrayPool<byte>.Shared.Return(input); }
    }
}

public class VolumeAllocatorIntegrityTests
{
    private static string TempDir()
    {
        return Path.Combine(Path.GetTempPath(), $"vai-{Guid.NewGuid()}");
    }

    [Fact]
    public void Allocate_BlockLevel_EncodesInFlags()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "test.txt");
            File.WriteAllText(path, "hello");

            var (items, _) = VolumeAllocator.Allocate(
                [new FileInfo(path)], dir, 1024 * 1024, 256, IntegrityLevel.Block);

            Assert.Single(items);
            var flags = items[0].Flags;
            Assert.Equal(IntegrityLevel.Block, (IntegrityLevel)(flags >> 3 & 3));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public void Allocate_VolumeLevel_EncodesInFlags()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "data.bin");
            File.WriteAllBytes(path, new byte[100]);

            var (items, _) = VolumeAllocator.Allocate(
                [new FileInfo(path)], dir, 1024 * 1024, 256, IntegrityLevel.Volume);

            Assert.Single(items);
            Assert.Equal(IntegrityLevel.Volume, (IntegrityLevel)(items[0].Flags >> 3 & 3));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public void Allocate_None_Default()
    {
        var dir = new DirectoryInfo(TempDir());
        try
        {
            dir.Create();
            var path = Path.Combine(dir.FullName, "f.txt");
            File.WriteAllText(path, "x");

            var (items, _) = VolumeAllocator.Allocate(
                [new FileInfo(path)], dir, 1024 * 1024, 256); // default None

            Assert.Single(items);
            Assert.Equal(IntegrityLevel.None, (IntegrityLevel)(items[0].Flags >> 3 & 3));
        }
        finally
        {
            try { dir.Delete(true); }
            catch { }
        }
    }
}