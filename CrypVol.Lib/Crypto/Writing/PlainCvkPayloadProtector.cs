using System.Text.Json;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Writing;

/// <summary>将序列化后的 Payload 原样作为密钥体写入，仅适用于 Plain 模式。</summary>
public sealed class PlainCvkPayloadProtector : ICvkPayloadProtector
{
    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(
        CvkHeader header,
        CvkPayload payload,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (header.KeyProtection != CvkKeyProtection.Plain)
            throw new InvalidOperationException("明文 Payload 保护器只能用于 Plain 模式。");

        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(
            JsonSerializer.SerializeToUtf8Bytes(payload, options));
    }
}