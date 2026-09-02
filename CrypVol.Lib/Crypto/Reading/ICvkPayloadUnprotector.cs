using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Reading;

/// <summary>将 CVK 文件密钥体解封为原始 Payload 的策略。</summary>
public interface ICvkPayloadUnprotector
{
    /// <summary>解封密钥体。</summary>
    ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken = default);
}