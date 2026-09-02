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
            var headerBytes = headerJson.ToArray();
            if (headerBytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) headerBytes = headerBytes[3..];
            using var headerDocument = JsonDocument.Parse(headerBytes, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false
            });
            ValidateHeaderJson(headerDocument.RootElement);
            header = JsonSerializer.Deserialize<CvkHeader>(headerDocument.RootElement.GetRawText(), jsonOptions ?? CreateJsonOptions())
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
        var validRoute = header.KeyProtection switch
        {
            CvkKeyProtection.Plain => header.KeyWrapAlgorithm == CvkKeyWrapAlgorithm.None,
            CvkKeyProtection.Password => header.KeyWrapAlgorithm is CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256 or CvkKeyWrapAlgorithm.PasswordArgon2Id,
            CvkKeyProtection.PublicKey => header.KeyWrapAlgorithm is CvkKeyWrapAlgorithm.RsaOaepSha256 or CvkKeyWrapAlgorithm.RsaOaepSha384
                or CvkKeyWrapAlgorithm.RsaOaepSha512 or CvkKeyWrapAlgorithm.EcdhP256 or CvkKeyWrapAlgorithm.EcdhP384 or CvkKeyWrapAlgorithm.EcdhP521,
            _ => false
        };
        if (!validRoute) throw new InvalidDataException("CVK 保护模式与封装算法不匹配。");
    }

    private static void ValidateHeaderJson(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("CVK Header 必须是 JSON 对象。");
        var known = new HashSet<string>(StringComparer.Ordinal)
        {
            "version", "keyProtection", "keyWrapAlgorithm", "label", "description", "comment", "createdAt", "generator"
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var required = new HashSet<string>(StringComparer.Ordinal) { "version", "keyProtection", "keyWrapAlgorithm" };
        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw new InvalidDataException($"CVK Header 字段重复：{property.Name}。");
            if (!known.Contains(property.Name)) throw new InvalidDataException($"CVK Header 存在未知字段：{property.Name}。");
            required.Remove(property.Name);
            switch (property.Name)
            {
                case "version":
                    if (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetUInt16(out _))
                        throw new InvalidDataException("CVK Header version 类型无效。");
                    break;
                case "keyProtection":
                    ValidateEnumString(property.Value, "Plain", "Password", "PublicKey");
                    break;
                case "keyWrapAlgorithm":
                    ValidateEnumString(property.Value, "None", "PasswordPbkdf2Sha256", "PasswordArgon2Id",
                        "RsaOaepSha256", "RsaOaepSha384", "RsaOaepSha512", "EcdhP256", "EcdhP384", "EcdhP521");
                    break;
                default:
                    if (property.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
                        throw new InvalidDataException($"CVK Header 字段类型无效：{property.Name}。");
                    break;
            }
        }
        if (required.Count != 0) throw new InvalidDataException("CVK Header 缺少必要字段。");
    }

    private static void ValidateEnumString(JsonElement value, params string[] allowed)
    {
        if (value.ValueKind != JsonValueKind.String || !allowed.Contains(value.GetString(), StringComparer.Ordinal))
            throw new InvalidDataException("CVK Header 枚举值无效。");
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
