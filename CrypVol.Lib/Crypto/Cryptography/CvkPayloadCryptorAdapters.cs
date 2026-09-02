using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>将统一双向实现适配到分离的读写接口。</summary>
public sealed class CvkPayloadProtectorAdapter(ICvkPayloadCryptor inner) : ICvkPayloadProtector
{
    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken = default)
    {
        return inner.ProtectAsync(header, payload, cancellationToken);
    }
}

/// <summary>将统一双向实现适配到分离的读写接口。</summary>
public sealed class CvkPayloadUnprotectorAdapter(ICvkPayloadCryptor inner) : ICvkPayloadUnprotector
{
    /// <inheritdoc />
    public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default)
    {
        return inner.UnprotectAsync(header, keyBody, cancellationToken);
    }
}