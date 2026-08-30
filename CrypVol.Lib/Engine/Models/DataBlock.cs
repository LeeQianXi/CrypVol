using System.Buffers;

namespace CrypVol.Lib.Engine.Models;

/// <summary>
///     处理流程中唯一的数据载体，由有效数据和描述该数据的元数据组成。
/// </summary>
public sealed class DataBlock : IDisposable
{
    private byte[]? _buffer;

    /// <summary>使用池化缓冲区创建数据块。</summary>
    /// <param name="buffer">由调用方移交所有权的池化缓冲区。</param>
    /// <param name="length">缓冲区中的有效数据长度。</param>
    /// <param name="metadata">数据块元数据。</param>
    public DataBlock(byte[] buffer, int length, BlockMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (length > buffer.Length) throw new ArgumentOutOfRangeException(nameof(length));

        _buffer = buffer;
        Length = length;
        Metadata = metadata;
    }

    /// <summary>数据块元数据。</summary>
    public BlockMetadata Metadata { get; }

    /// <summary>有效数据长度。</summary>
    public int Length { get; }

    /// <summary>池化缓冲区。</summary>
    public byte[] Buffer => _buffer ?? throw new ObjectDisposedException(nameof(DataBlock));

    /// <summary>有效数据的只读视图。</summary>
    public ReadOnlyMemory<byte> Data => Buffer.AsMemory(0, Length);

    /// <summary>将缓冲区归还共享池。</summary>
    public void Dispose()
    {
        var buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
    }
}