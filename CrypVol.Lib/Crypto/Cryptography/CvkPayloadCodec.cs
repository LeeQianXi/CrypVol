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
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(payload.RecipientKeys);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, Options);
        using var document = JsonDocument.Parse(bytes);
        ValidatePayloadJson(document.RootElement);
        return bytes;
    }

    public static CvkPayload Decode(ReadOnlySpan<byte> bytes)
    {
        try
        {
            using var json = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false
            });
            ValidatePayloadJson(json.RootElement);
            var payload = JsonSerializer.Deserialize<CvkPayload>(json.RootElement.GetRawText(), Options)
                          ?? throw new InvalidDataException("CVK Payload 为空。");
            if (payload.Cek.Length != 32) throw new InvalidDataException("CVK CEK 必须恰好为 32 字节。");
            return payload;
        }
        catch (JsonException ex) { throw new InvalidDataException("CVK Payload 无效。", ex); }
    }

    public static byte[] EncodeHeader(CvkHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);
        return JsonSerializer.SerializeToUtf8Bytes(header, Options);
    }

    private static void ValidatePayloadJson(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("CVK Payload 必须是 JSON 对象。");
        var names = new HashSet<string>(StringComparer.Ordinal);
        JsonElement cek = default, recipients = default;
        foreach (var property in root.EnumerateObject())
        {
            if (!names.Add(property.Name)) throw new InvalidDataException($"CVK Payload 字段重复：{property.Name}。");
            switch (property.Name)
            {
                case "cek": cek = property.Value; break;
                case "recipientKeys": recipients = property.Value; break;
                default: throw new InvalidDataException($"CVK Payload 存在未知字段：{property.Name}。");
            }
        }

        if (!names.Contains("cek") || cek.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("CVK Payload 缺少有效 cek。");
        if (!names.Contains("recipientKeys") || recipients.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("CVK Payload 缺少有效 recipientKeys。");
        byte[] cekBytes;
        try { cekBytes = Convert.FromBase64String(cek.GetString()!); }
        catch (Exception ex) when (ex is FormatException or ArgumentNullException)
        {
            throw new InvalidDataException("CVK CEK 编码无效。", ex);
        }

        if (cekBytes.Length != 32) throw new InvalidDataException("CVK CEK 必须恰好为 32 字节。");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in recipients.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("接收者必须是 JSON 对象。");
            var fields = new HashSet<string>(StringComparer.Ordinal);
            JsonElement keyId = default, algorithm = default, publicKey = default;
            foreach (var property in item.EnumerateObject())
            {
                if (!fields.Add(property.Name)) throw new InvalidDataException($"接收者字段重复：{property.Name}。");
                switch (property.Name)
                {
                    case "keyId": keyId = property.Value; break;
                    case "algorithm": algorithm = property.Value; break;
                    case "publicKey": publicKey = property.Value; break;
                    case "comment":
                        if (property.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
                            throw new InvalidDataException("comment 类型无效。");
                        break;
                    default: throw new InvalidDataException($"接收者存在未知字段：{property.Name}。");
                }
            }

            if (keyId.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(keyId.GetString()) ||
                !ids.Add(keyId.GetString()!))
                throw new InvalidDataException("接收者 KeyId 缺失、为空或重复。");
            if (algorithm.ValueKind != JsonValueKind.String || algorithm.GetString() is not ("RSA" or "ECDH"))
                throw new InvalidDataException("接收者算法不受支持。");
            if (publicKey.ValueKind != JsonValueKind.String) throw new InvalidDataException("接收者公钥类型无效。");
            try
            {
                if (Convert.FromBase64String(publicKey.GetString()!).Length == 0)
                    throw new InvalidDataException("接收者公钥不能为空。");
            }
            catch (FormatException ex) { throw new InvalidDataException("接收者公钥编码无效。", ex); }
        }
    }
}