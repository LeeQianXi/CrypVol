using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CrypVol.Lib.Crypto;

/// <summary>CVK v3 容器的固定格式常量。</summary>
internal static class CvkFormat
{
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("CVK3");
    public const byte Version = 1;
    public const byte Flags = 0;
    public const int HeaderSize = 14;
    public const int IntegritySize = 32;
    public const int MaxSectionLength = 16 * 1024 * 1024;
}

/// <summary>CVK 明文元数据；其内容用于选择对应的密钥体解封路线。</summary>
public sealed record CvkMetadataPayload(
    EncryptionMode ProtectionMode,
    EncryptionAlgorithm Algorithm,
    DateTimeOffset? CreatedAt,
    string? Label,
    string? Description,
    string? Generator,
    string? Comment,
    IReadOnlyList<string> KeyIds,
    int KeyBodyLength,
    string Integrity = "SHA-256");

/// <summary>CVK 元数据统一 JSON 配置。</summary>
internal static class CvkJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };
}
