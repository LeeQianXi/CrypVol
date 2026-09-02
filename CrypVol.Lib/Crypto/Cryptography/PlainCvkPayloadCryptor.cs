using System.Text.Json;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>Plain 模式的密钥体封装和解封实现。</summary>
public sealed class PlainCvkPayloadCryptor : ICvkPayloadCryptor
{
    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken = default)
    {
        EnsureHeader(header);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(JsonSerializer.SerializeToUtf8Bytes(payload,
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            }));
    }

    /// <inheritdoc />
    public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default)
    {
        EnsureHeader(header);
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

    private static void EnsureHeader(CvkHeader header)
    {
        if (header.KeyProtection != CvkKeyProtection.Plain || header.KeyWrapAlgorithm != CvkKeyWrapAlgorithm.None)
            throw new InvalidOperationException("Plain 密钥体实现只能用于 Plain/None。");
    }
}