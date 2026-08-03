using System.Security.Cryptography;
using CrypVol.Lib;
using Xunit;

namespace CrypVol.Tests;

public class FileEntryHeaderTests
{
    // ── Constants ──

    [Fact]
    public void MagicHeader_IsCorrectValue()
    {
        Assert.Equal(0x48505643u, FileEntryHeader.MagicHeader);
    }

    [Fact]
    public void HeaderSize_Is256()
    {
        Assert.Equal(256, FileEntryHeader.HeaderSize);
    }

    [Fact]
    public void EncryptedHeaderSize_Is284()
    {
        Assert.Equal(284, FileEntryHeader.EncryptedHeaderSize);
    }

    // ── Default Constructor ──

    [Fact]
    public void DefaultConstructor_SetsMagic()
    {
        var hdr = new FileEntryHeader();
        Assert.Equal(FileEntryHeader.MagicHeader, hdr.Magic);
    }

    [Fact]
    public void DefaultConstructor_SetsZeroFields()
    {
        var hdr = new FileEntryHeader();
        Assert.Equal(0u, hdr.FileId);
        Assert.Equal(0, hdr.Flags);
        Assert.Equal(0u, hdr.FragmentIndex);
        Assert.Equal(0L, hdr.SizeOrTotal);
    }

    // ── ToBytes ──

    [Fact]
    public void ToBytes_Returns256ByteArray()
    {
        var hdr = new FileEntryHeader();
        var bytes = hdr.ToBytes();
        Assert.Equal(256, bytes.Length);
    }

    [Fact]
    public void ToBytes_ContainsMagicAtStart()
    {
        var hdr = new FileEntryHeader();
        var bytes = hdr.ToBytes();
        Assert.Equal(FileEntryHeader.MagicHeader, BitConverter.ToUInt32(bytes, 0));
    }

    [Fact]
    public void ToBytes_PreservesFileId()
    {
        var hdr = new FileEntryHeader { FileId = 0xDEADBEEF12345678 };
        var bytes = hdr.ToBytes();
        Assert.Equal(0xDEADBEEF12345678u, BitConverter.ToUInt64(bytes, 4));
    }

    [Fact]
    public void ToBytes_PreservesFlags()
    {
        var hdr = new FileEntryHeader { Flags = 0xAB };
        var bytes = hdr.ToBytes();
        Assert.Equal(0xAB, bytes[12]);
    }

    [Fact]
    public void ToBytes_PreservesFragmentIndex()
    {
        var hdr = new FileEntryHeader { FragmentIndex = 42 };
        var bytes = hdr.ToBytes();
        Assert.Equal(42u, BitConverter.ToUInt32(bytes, 13));
    }

    [Fact]
    public void ToBytes_PreservesSizeOrTotal()
    {
        var hdr = new FileEntryHeader { SizeOrTotal = 123456789 };
        var bytes = hdr.ToBytes();
        Assert.Equal(123456789L, BitConverter.ToInt64(bytes, 17));
    }

    // ── SetFilePath ──

    [Fact]
    public void SetFilePath_WritesUtf8Path()
    {
        var hdr = new FileEntryHeader();
        hdr.SetFilePath("test.txt");
        var bytes = hdr.ToBytes();
        var pathBytes = bytes.Skip(25).TakeWhile(b => b != 0).ToArray();
        var path = System.Text.Encoding.UTF8.GetString(pathBytes);
        Assert.Equal("test.txt", path);
    }

    [Fact]
    public void SetFilePath_NullTerminates()
    {
        var hdr = new FileEntryHeader();
        hdr.SetFilePath("a");
        var bytes = hdr.ToBytes();
        Assert.Equal(0, bytes[26]); // after 'a'
    }

    [Fact]
    public void SetFilePath_TruncatesOver231Bytes()
    {
        var hdr = new FileEntryHeader();
        var longPath = new string('x', 300);
        hdr.SetFilePath(longPath);
        var bytes = hdr.ToBytes();
        var pathBytes = bytes.Skip(25).TakeWhile(b => b != 0).ToArray();
        Assert.True(pathBytes.Length <= 230);
    }

    [Fact]
    public void SetFilePath_HandlesEmptyString()
    {
        var hdr = new FileEntryHeader();
        hdr.SetFilePath("");
        var bytes = hdr.ToBytes();
        Assert.Equal(0, bytes[25]); // immediately null-terminated
    }

    [Fact]
    public void SetFilePath_HandlesUnicode()
    {
        var hdr = new FileEntryHeader();
        hdr.SetFilePath("测试文件.txt");
        var bytes = hdr.ToBytes();
        var pathBytes = bytes.Skip(25).TakeWhile(b => b != 0).ToArray();
        var path = System.Text.Encoding.UTF8.GetString(pathBytes);
        Assert.Equal("测试文件.txt", path);
    }

    // ── Encrypt / Decrypt Roundtrip ──

    [Fact]
    public void EncryptDecrypt_RoundTrip_PreservesAllFields()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var original = new FileEntryHeader
        {
            FileId = 12345,
            Flags = 3,
            FragmentIndex = 7,
            SizeOrTotal = 99999
        };
        original.SetFilePath("folder/sub/file.txt");

        var encrypted = FileEntryHeader.Encrypt(original, cek);
        Assert.Equal(FileEntryHeader.EncryptedHeaderSize, encrypted.Length);

        var decrypted = FileEntryHeader.Decrypt(encrypted, cek);
        Assert.Equal(original.FileId, decrypted.FileId);
        Assert.Equal(original.Flags, decrypted.Flags);
        Assert.Equal(original.FragmentIndex, decrypted.FragmentIndex);
        Assert.Equal(original.SizeOrTotal, decrypted.SizeOrTotal);
    }

    [Fact]
    public void Encrypt_ProducesDifferentOutputEachTime()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var hdr = new FileEntryHeader();

        var e1 = FileEntryHeader.Encrypt(hdr, cek);
        var e2 = FileEntryHeader.Encrypt(hdr, cek);

        // Different nonce => different ciphertext
        Assert.False(e1.AsSpan(4, 12).SequenceEqual(e2.AsSpan(4, 12)));
    }

    [Fact]
    public void Encrypt_PreservesMagicInPlaintext()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var hdr = new FileEntryHeader();

        var encrypted = FileEntryHeader.Encrypt(hdr, cek);
        Assert.Equal(FileEntryHeader.MagicHeader, BitConverter.ToUInt32(encrypted, 0));
    }

    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var cek1 = RandomNumberGenerator.GetBytes(32);
        var cek2 = RandomNumberGenerator.GetBytes(32);
        var hdr = new FileEntryHeader();

        var encrypted = FileEntryHeader.Encrypt(hdr, cek1);
        Assert.ThrowsAny<Exception>(() => FileEntryHeader.Decrypt(encrypted, cek2));
    }

    // ── ReadMagic ──

    [Fact]
    public void ReadMagic_ReturnsCorrectMagic()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var hdr = new FileEntryHeader();
        var encrypted = FileEntryHeader.Encrypt(hdr, cek);

        Assert.Equal(FileEntryHeader.MagicHeader, FileEntryHeader.ReadMagic(encrypted));
    }

    [Fact]
    public void ReadMagic_FromPlainBytes()
    {
        var hdr = new FileEntryHeader();
        var bytes = hdr.ToBytes();
        Assert.Equal(FileEntryHeader.MagicHeader, FileEntryHeader.ReadMagic(bytes));
    }

    // ── FileEntryHeaderFlagsEnum ──

    [Fact]
    public void FlagsEnum_Full_IsZero()
    {
        Assert.Equal(0, (byte)FileEntryHeaderFlagsEnum.Full);
    }

    [Fact]
    public void FlagsEnum_HasExpectedValues()
    {
        Assert.Equal(1, (byte)FileEntryHeaderFlagsEnum.CrossHead);
        Assert.Equal(2, (byte)FileEntryHeaderFlagsEnum.CrossMid);
        Assert.Equal(3, (byte)FileEntryHeaderFlagsEnum.CrossTail);
        Assert.Equal(4, (byte)FileEntryHeaderFlagsEnum.HasExtendedHeader);
    }

    [Fact]
    public void Flags_CanCombineWithBitwiseOr()
    {
        var flags = (byte)(FileEntryHeaderFlagsEnum.CrossHead | FileEntryHeaderFlagsEnum.HasExtendedHeader);
        Assert.Equal(5, flags);
    }

    // ── Edge Cases ──

    [Fact]
    public void Encrypt_DifferentCekDifferentOutput()
    {
        var cek1 = RandomNumberGenerator.GetBytes(32);
        var cek2 = RandomNumberGenerator.GetBytes(32);
        var hdr = new FileEntryHeader { FileId = 1 };
        hdr.SetFilePath("test");

        var e1 = FileEntryHeader.Encrypt(hdr, cek1);
        var e2 = FileEntryHeader.Encrypt(hdr, cek2);

        // Both should decrypt correctly with their own CEK
        var d1 = FileEntryHeader.Decrypt(e1, cek1);
        var d2 = FileEntryHeader.Decrypt(e2, cek2);
        Assert.Equal(d1.FileId, d2.FileId);
    }

    [Fact]
    public void Decrypt_TamperedData_Throws()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var hdr = new FileEntryHeader();
        var encrypted = FileEntryHeader.Encrypt(hdr, cek);

        // Tamper with ciphertext
        encrypted[100] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => FileEntryHeader.Decrypt(encrypted, cek));
    }
}
