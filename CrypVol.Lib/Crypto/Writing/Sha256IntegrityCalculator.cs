using System.Security.Cryptography;

namespace CrypVol.Lib.Crypto.Writing;

/// <summary>使用 SHA-256 计算 CVK 文件完整性段。</summary>
/// <remarks>密钥体应由 Payload 保护策略提供认证；此值用于检测文件段的意外篡改或损坏。</remarks>
public sealed class Sha256IntegrityCalculator : ICvkIntegrityCalculator
{
    /// <inheritdoc />
    public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody)
    {
        var data = new byte[headerJson.Length + keyBody.Length];
        headerJson.Span.CopyTo(data);
        keyBody.Span.CopyTo(data.AsSpan(headerJson.Length));
        return SHA256.HashData(data);
    }
}