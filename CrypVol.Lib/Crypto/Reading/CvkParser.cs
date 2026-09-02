using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Reading;

/// <summary>严格解析 CVK 三段式文件，不执行密钥解封。</summary>
public static class CvkParser
{
    private const int PrefixSize = 16;
    private const int MaxHeaderLength = 1024 * 1024;
    private const int MaxKeyBodyLength = 256 * 1024 * 1024;
    private const int MaxIntegrityLength = 4096;
    private static readonly byte[] Magic = [.. "CVK1"u8];

    /// <summary>解析 CVK 文件字节。</summary>
    public static CvkParsedFile Parse(ReadOnlyMemory<byte> data,
        JsonSerializerOptions? jsonOptions = null)
    {
        if (data.Length < PrefixSize) throw new InvalidDataException("CVK 文件长度不足。");
        var span = data.Span;
        if (!span[..Magic.Length].SequenceEqual(Magic)) throw new InvalidDataException("不是有效的 CVK 文件。");

        var headerLength = ReadLength(span[4..8], MaxHeaderLength, "Header");
        var bodyLength = ReadLength(span[8..12], MaxKeyBodyLength, "密钥体");
        var integrityLength = ReadLength(span[12..16], MaxIntegrityLength, "完整性段");
        var expected = (long)PrefixSize + headerLength + bodyLength + integrityLength;
        if (expected != data.Length) throw new InvalidDataException("CVK 段长度与文件长度不一致。");

        var offset = PrefixSize;
        var headerJson = data.Slice(offset, headerLength);
        offset += headerLength;
        var keyBody = data.Slice(offset, bodyLength);
        offset += bodyLength;
        var integrity = data.Slice(offset, integrityLength);
        CvkHeader header;
        try
        {
            header = JsonSerializer.Deserialize<CvkHeader>(headerJson.Span, jsonOptions ?? CreateJsonOptions())
                     ?? throw new InvalidDataException("CVK Header 为空。");
        }
        catch (JsonException ex) { throw new InvalidDataException("CVK Header JSON 无效。", ex); }

        ValidateHeader(header);
        return new CvkParsedFile(header, headerJson.ToArray(), keyBody.ToArray(), integrity.ToArray());
    }

    private static int ReadLength(ReadOnlySpan<byte> bytes, int max, string name)
    {
        var value = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        if (value == 0 || value > max) throw new InvalidDataException($"CVK {name} 长度无效。");
        return checked((int)value);
    }

    private static void ValidateHeader(CvkHeader header)
    {
        if (header.Version == 0) throw new InvalidDataException("CVK 版本无效。");
        if (!Enum.IsDefined(header.KeyProtection)) throw new InvalidDataException("CVK 保护模式无效。");
        if (!Enum.IsDefined(header.KeyWrapAlgorithm)) throw new InvalidDataException("CVK 封装算法无效。");
        if (header.KeyProtection == CvkKeyProtection.Plain && header.KeyWrapAlgorithm != CvkKeyWrapAlgorithm.None)
            throw new InvalidDataException("Plain 模式不能携带密钥封装算法。");
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        return new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters =
            {
                new JsonStringEnumConverter()
            }
        };
    }
}