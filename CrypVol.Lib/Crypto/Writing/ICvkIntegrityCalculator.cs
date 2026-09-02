namespace CrypVol.Lib.Crypto.Writing;

/// <summary>计算 CVK 文件完整性段的策略。</summary>
public interface ICvkIntegrityCalculator
{
    /// <summary>根据 Header JSON 和密钥体计算完整性值。</summary>
    ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody);
}