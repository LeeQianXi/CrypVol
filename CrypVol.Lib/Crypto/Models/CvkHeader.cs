using System.Text.Json.Serialization;

namespace CrypVol.Lib.Crypto.Models;

/// <summary>CVK Header 的公开元数据和解封路由信息。</summary>
/// <remarks>该类型同时是 Header 的内存契约和 JSON 对象契约，不再维护重复的 HeaderJson 类型。</remarks>
public sealed record CvkHeader(
    [property: JsonPropertyName("version")]
    ushort Version,
    [property: JsonPropertyName("keyProtection")]
    CvkKeyProtection KeyProtection,
    [property: JsonPropertyName("keyWrapAlgorithm")]
    CvkKeyWrapAlgorithm KeyWrapAlgorithm,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("description")]
    string? Description,
    [property: JsonPropertyName("comment")]
    string? Comment,
    [property: JsonPropertyName("createdAt")]
    DateTimeOffset? CreatedAt,
    [property: JsonPropertyName("generator")]
    string? Generator);