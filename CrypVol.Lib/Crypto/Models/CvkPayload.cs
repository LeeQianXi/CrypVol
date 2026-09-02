using CrypVol.Lib.Crypto.Keys;

namespace CrypVol.Lib.Crypto.Models;

/// <summary>CVK Payload 的原始私密内容。</summary>
/// <remarks>它不是文件密文段；文件写入器负责将其转换为封装后的密钥体。</remarks>
public sealed record CvkPayload(
    ReadOnlyMemory<byte> Cek,
    IReadOnlyList<AsymmetricRecipientKey> RecipientKeys);