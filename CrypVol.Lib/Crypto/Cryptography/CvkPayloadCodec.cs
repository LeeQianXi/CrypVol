using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>提供 CVK Payload 的规范化 JSON 编解码。</summary>
internal static class CvkPayloadCodec
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    public static byte[] Encode(CvkPayload payload)
    {
        return JsonSerializer.SerializeToUtf8Bytes(payload, Options);
    }

    public static CvkPayload Decode(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<CvkPayload>(bytes, Options)
                   ?? throw new InvalidDataException("CVK Payload 为空。");
        }
        catch (JsonException ex) { throw new InvalidDataException("CVK Payload 无效。", ex); }
    }

    public static byte[] EncodeHeader(CvkHeader header)
    {
        return JsonSerializer.SerializeToUtf8Bytes(header, Options);
    }
}