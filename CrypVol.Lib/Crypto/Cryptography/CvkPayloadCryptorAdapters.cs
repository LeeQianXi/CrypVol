using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>将统一双向实现适配到分离的读写接口。</summary>
public sealed class CvkPayloadProtectorAdapter(ICvkPayloadCryptor inner) : ICvkPayloadProtector
{
    private readonly ICvkPayloadCryptor _inner = inner
        ?? throw new ArgumentNullException(nameof(inner));

    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken = default)
    {
        return _inner.ProtectAsync(header, payload, cancellationToken);
    }
}

/// <summary>将统一双向实现适配到分离的读写接口。</summary>
public sealed class CvkPayloadUnprotectorAdapter(ICvkPayloadCryptor inner) : ICvkPayloadUnprotector
{
    private readonly ICvkPayloadCryptor _inner = inner
        ?? throw new ArgumentNullException(nameof(inner));

    /// <inheritdoc />
    public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default)
    {
        return _inner.UnprotectAsync(header, keyBody, cancellationToken);
    }
}
