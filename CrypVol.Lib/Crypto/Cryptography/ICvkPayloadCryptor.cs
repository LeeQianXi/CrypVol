using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>CVK 密钥体的统一双向保护接口。</summary>
/// <remarks>同一实现必须同时保证封装和解封使用兼容的格式与参数。</remarks>
public interface ICvkPayloadCryptor
{
    /// <summary>将原始 Payload 封装为文件密钥体。</summary>
    ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken = default);

    /// <summary>将文件密钥体解封为原始 Payload。</summary>
    ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default);
}