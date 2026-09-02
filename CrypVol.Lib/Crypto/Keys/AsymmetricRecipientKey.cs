using System.Text.Json.Serialization;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>公钥接收者的原始可序列化材料；不包含私钥。</summary>
public sealed record AsymmetricRecipientKey(
    [property: JsonPropertyName("keyId")] string KeyId,
    [property: JsonPropertyName("algorithm")]
    string Algorithm,
    [property: JsonPropertyName("publicKey")]
    ReadOnlyMemory<byte> PublicKeyBytes,
    [property: JsonPropertyName("comment")]
    string? Comment = null);