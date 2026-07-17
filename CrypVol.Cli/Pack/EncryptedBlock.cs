using System.Buffers;

namespace CrypVol.Cli.Pack;

public sealed class EncryptedBlock : IDisposable
{
    public TaskItem Metadata { get; init; }
    public Memory<byte> Data { get; init; } // 压缩+加密后的密文
    public int OriginalLength { get; init; } // 压缩前原始长度（用于头部 SizeOrTotal）

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(Data.ToArray());
    }
}