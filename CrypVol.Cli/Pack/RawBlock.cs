using System.Buffers;

namespace CrypVol.Cli.Pack;

public sealed class RawBlock : IDisposable
{
    public BlockHeader Metadata { get; init; }

    /// 从 ArrayPool 租借的内存
    public Memory<byte> Data { get; init; }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(Data.ToArray());
    }
}