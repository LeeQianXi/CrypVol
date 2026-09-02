using System.Text.Json;
using CrypVol.Lib.Crypto.Cryptography;
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
        if (header.KeyProtection != CvkKeyProtection.Plain || header.KeyWrapAlgorithm != CvkKeyWrapAlgorithm.None)
            throw new InvalidOperationException("明文 Payload 解封器只能用于 Plain 模式。");
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return ValueTask.FromResult(CvkPayloadCodec.Decode(keyBody.Span));
        }
        catch (JsonException ex) { throw new InvalidDataException("CVK Payload JSON 无效。", ex); }
    }
}
