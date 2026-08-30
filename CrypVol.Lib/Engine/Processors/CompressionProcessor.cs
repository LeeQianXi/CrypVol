using System.Buffers;
using System.IO.Compression;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责将数据块压缩为 GZip 数据。</summary>
public sealed class CompressionProcessor : DataProcessorBase
{
    private readonly CompressionLevel _level;

    /// <summary>创建压缩处理器。</summary>
    /// <param name="compressionLevel">压缩级别。</param>
    public CompressionProcessor(int compressionLevel)
    {
        _level = compressionLevel switch
        {
            0 => CompressionLevel.NoCompression,
            <= 3 => CompressionLevel.Fastest,
            <= 6 => CompressionLevel.Optimal,
            _ => CompressionLevel.SmallestSize
        };
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        using var stream = new MemoryStream();
        using (var gzip = new GZipStream(stream, _level, true))
        {
            gzip.Write(block.Buffer, 0, block.Length);
        }

        var data = stream.ToArray();
        var buffer = ArrayPool<byte>.Shared.Rent(data.Length);
        data.CopyTo(buffer, 0);
        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, data.Length, block.Metadata));
    }
}