using System.Buffers;

namespace CrypVol.Cli.Pack;

public sealed class EncryptedBlock : IDisposable
{
    public BlockHeader Metadata { get; init; }

    /// 从 ArrayPool 租借的内存
    public Memory<byte> Data { get; init; }

    /// 压缩前原始长度（用于头部 SizeOrTotal）
    public int OriginalLength { get; init; }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(Data.ToArray());
    }
}