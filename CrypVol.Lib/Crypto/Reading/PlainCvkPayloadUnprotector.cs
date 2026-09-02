using System.Text.Json;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Reading;

/// <summary>解析 Plain 模式的明文密钥体。</summary>
public sealed class PlainCvkPayloadUnprotector : ICvkPayloadUnprotector
{
    /// <inheritdoc />
    public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (header.KeyProtection != CvkKeyProtection.Plain)
            throw new InvalidOperationException("明文 Payload 解封器只能用于 Plain 模式。");
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var payload = JsonSerializer.Deserialize<CvkPayload>(keyBody.Span,
                new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
            return ValueTask.FromResult(payload ?? throw new InvalidDataException("CVK Payload 为空。"));
        }
        catch (JsonException ex) { throw new InvalidDataException("CVK Payload JSON 无效。", ex); }
    }
}
