using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CrypVol.Lib.Crypto.Writing;

/// <summary>使用 SHA-256 计算 CVK 文件完整性段。</summary>
/// <remarks>密钥体应由 Payload 保护策略提供认证；此值用于检测文件段的意外篡改或损坏。</remarks>
public sealed class Sha256IntegrityCalculator : ICvkIntegrityCalculator
{
    /// <inheritdoc />
    public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody)
    {
        var data = new byte[8 + headerJson.Length + keyBody.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(data, checked((uint)headerJson.Length));
        headerJson.Span.CopyTo(data.AsSpan(4));
        var bodyOffset = 4 + headerJson.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(bodyOffset), checked((uint)keyBody.Length));
        keyBody.Span.CopyTo(data.AsSpan(bodyOffset + 4));
        return SHA256.HashData(data);
    }
}
