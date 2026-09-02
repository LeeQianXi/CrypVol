using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using Xunit;

namespace CrypVol.Tests;

/// <summary>覆盖 CVK 文件格式的边界长度、语义篡改和 Writer 参数校验。</summary>
public sealed class CvkFormatBoundaryTests
{
    [Fact]
    public async Task TruncatedFile_IsRejectedByExactLengthCheck()
    {
        var file = await WritePlainAsync();
        try
        {
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            var truncated = bytes[..^1];
            await File.WriteAllBytesAsync(file.FullName, truncated);

            await Assert.ThrowsAsync<InvalidDataException>(() => CvkOperations.LoadAsync(file));
        }
        finally { Delete(file); }
    }

    [Fact]
    public async Task AppendedFile_IsRejectedByExactLengthCheck()
    {
        var file = await WritePlainAsync();
        try
        {
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            var appended = new byte[bytes.Length + 1];
            bytes.CopyTo(appended, 0);
            await File.WriteAllBytesAsync(file.FullName, appended);

            await Assert.ThrowsAsync<InvalidDataException>(() => CvkOperations.LoadAsync(file));
        }
        finally { Delete(file); }
    }

    [Fact]
    public async Task ValidHeaderSemanticTampering_IsRejectedByIntegrityCheck()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            document.Comment = "semantic-tamper-marker";
            await CvkOperations.WriteAsync(document, file);
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            var headerLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4)));
            var headerOffset = 16;
            var marker = Encoding.UTF8.GetBytes("semantic-tamper-marker");
            var position = bytes.AsSpan(headerOffset, headerLength).IndexOf(marker);
            Assert.True(position >= 0);
            bytes[headerOffset + position + marker.Length - 1] = (byte)'x';
            await File.WriteAllBytesAsync(file.FullName, bytes);

            await Assert.ThrowsAsync<CryptographicException>(() => CvkOperations.LoadAsync(file));
        }
        finally { Delete(file); }
    }

    [Fact]
    public void Parser_RejectsZeroHeaderLength()
    {
        var bytes = ValidPlainBytes();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), 0);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Fact]
    public void Parser_RejectsZeroKeyBodyLength()
    {
        var bytes = ValidPlainBytes();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), 0);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Fact]
    public void Parser_RejectsZeroIntegrityLength()
    {
        var bytes = ValidPlainBytes();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), 0);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Theory]
    [InlineData(4_194_305u)]
    [InlineData(uint.MaxValue)]
    public void Parser_RejectsHeaderLengthAboveConfiguredLimit(uint length)
    {
        var bytes = ValidPlainBytes();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), length);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Theory]
    [InlineData(268_435_457u)]
    [InlineData(uint.MaxValue)]
    public void Parser_RejectsKeyBodyLengthAboveConfiguredLimit(uint length)
    {
        var bytes = ValidPlainBytes();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), length);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Theory]
    [InlineData(4097u)]
    [InlineData(uint.MaxValue)]
    public void Parser_RejectsIntegrityLengthAboveConfiguredLimit(uint length)
    {
        var bytes = ValidPlainBytes();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), length);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{} trailing")]
    [InlineData("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}x")]
    public void Parser_RejectsNullOrTrailingHeaderJson(string json)
    {
        var bytes = ValidPlainBytes();
        var headerLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4)));
        var replacement = Encoding.UTF8.GetBytes(json);
        var rebuilt = new byte[bytes.Length - headerLength + replacement.Length];
        bytes.AsSpan(0, 16).CopyTo(rebuilt);
        BinaryPrimitives.WriteUInt32LittleEndian(rebuilt.AsSpan(4, 4), (uint)replacement.Length);
        replacement.CopyTo(rebuilt.AsSpan(16));
        bytes.AsSpan(16 + headerLength).CopyTo(rebuilt.AsSpan(16 + replacement.Length));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(rebuilt));
    }

    [Fact]
    public void Parser_ReturnsOwnedSegmentCopies()
    {
        var bytes = ValidPlainBytes();
        var parsed = CvkParser.Parse(bytes);
        var originalHeader = parsed.HeaderJson.ToArray();
        var originalBody = parsed.KeyBody.ToArray();
        var originalIntegrity = parsed.Integrity.ToArray();

        Array.Fill(bytes, (byte)0);

        Assert.Equal(originalHeader, parsed.HeaderJson.ToArray());
        Assert.Equal(originalBody, parsed.KeyBody.ToArray());
        Assert.Equal(originalIntegrity, parsed.Integrity.ToArray());
    }

    [Fact]
    public async Task Writer_RejectsEmptyCek()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
        document.Cek = [];
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new CrypVol.Lib.Crypto.Writing.CvkWriter(
                new CrypVol.Lib.Crypto.Writing.PlainCvkPayloadProtector()).WriteAsync(
                    document, new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}.cvk"))));
    }

    private static async Task<FileInfo> WritePlainAsync()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}.cvk"));
        await CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
        return file;
    }

    private static byte[] ValidPlainBytes()
    {
        var file = WritePlainAsync().GetAwaiter().GetResult();
        try { return File.ReadAllBytes(file.FullName); }
        finally { Delete(file); }
    }

    private static void Delete(FileInfo file)
    {
        if (file.Exists) file.Delete();
    }
}
