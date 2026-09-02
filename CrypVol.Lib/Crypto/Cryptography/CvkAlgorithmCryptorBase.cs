using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>绑定单一 CVK 算法路由的处理器基类。</summary>
public abstract class CvkAlgorithmCryptorBase(
    CvkKeyProtection protection,
    CvkKeyWrapAlgorithm wrapAlgorithm) : ICvkPayloadCryptor
{
    /// <summary>处理器绑定的保护模式。</summary>
    protected CvkKeyProtection Protection { get; } = protection;

    /// <summary>处理器绑定的封装算法。</summary>
    protected CvkKeyWrapAlgorithm WrapAlgorithm { get; } = wrapAlgorithm;

    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        EnsureRoute(header);
        return ProtectCoreAsync(header, payload, cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default)
    {
        EnsureRoute(header);
        return UnprotectCoreAsync(header, keyBody, cancellationToken);
    }

    /// <summary>执行具体封装。</summary>
    protected abstract ValueTask<ReadOnlyMemory<byte>> ProtectCoreAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken);

    /// <summary>执行具体解封。</summary>
    protected abstract ValueTask<CvkPayload> UnprotectCoreAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken);

    private void EnsureRoute(CvkHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (header.KeyProtection != Protection || header.KeyWrapAlgorithm != WrapAlgorithm)
            throw new InvalidOperationException($"处理器路由不匹配：需要 {Protection}/{WrapAlgorithm}。");
    }
}
