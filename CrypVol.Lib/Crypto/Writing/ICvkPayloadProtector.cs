using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Writing;

/// <summary>将 CVK Payload 转换为文件密钥体的策略。</summary>
public interface ICvkPayloadProtector
{
    /// <summary>保护 Payload。</summary>
    /// <param name="header">公开 Header。</param>
    /// <param name="payload">待保护的原始 Payload。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    ValueTask<ReadOnlyMemory<byte>> ProtectAsync(
        CvkHeader header,
        CvkPayload payload,
        CancellationToken cancellationToken = default);
}