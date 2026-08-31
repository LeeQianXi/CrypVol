using System.Buffers;
using System.IO.Compression;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责解压 GZip 数据块。</summary>
public sealed class DecompressionProcessor : DataProcessorBase
{
    private const int MaxDecompressedBlockSize = 64 * 1024 * 1024;

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        using var source = new MemoryStream(block.Buffer, 0, block.Length, false);
        using var gzip = new GZipStream(source, CompressionMode.Decompress);
        using var destination = new MemoryStream(Math.Min(block.Length * 2, MaxDecompressedBlockSize));
        var temp = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            int read;
            while ((read = gzip.Read(temp, 0, temp.Length)) > 0)
            {
                if (destination.Length + read > MaxDecompressedBlockSize)
                    throw new InvalidDataException("解压后的数据块超过 64MiB 上限。");
                destination.Write(temp, 0, read);
            }

            if (!destination.TryGetBuffer(out var segment)) throw new InvalidOperationException("无法读取解压缓冲区。");
            var length = checked((int)destination.Length);
            var buffer = ArrayPool<byte>.Shared.Rent(length);
            segment.AsSpan(0, length).CopyTo(buffer);
            return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, length, block.Metadata));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(temp, clearArray: true);
        }
    }
}
