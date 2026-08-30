using System.Buffers;
using System.IO.Compression;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责解压 GZip 数据块。</summary>
public sealed class DecompressionProcessor : DataProcessorBase
{
    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        using var source = new MemoryStream(block.Buffer, 0, block.Length, false);
        using var gzip = new GZipStream(source, CompressionMode.Decompress);
        using var destination = new MemoryStream();
        gzip.CopyTo(destination);
        var data = destination.ToArray();
        var buffer = ArrayPool<byte>.Shared.Rent(data.Length);
        data.CopyTo(buffer, 0);
        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, data.Length, block.Metadata));
    }
}