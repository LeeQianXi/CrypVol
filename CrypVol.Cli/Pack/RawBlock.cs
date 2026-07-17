using System.Buffers;

namespace CrypVol.Cli.Pack;

public sealed class RawBlock : IDisposable
{
    public TaskItem Metadata { get; init; }

    /// 从 ArrayPool 租借的内存
    public Memory<byte> Data { get; init; }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(Data.ToArray());
    }
    // 注意：实际使用 MemoryManager 包装，此处示意
}