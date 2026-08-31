using System.Buffers;
using System.IO.Compression;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责将数据块压缩为 GZip 数据。</summary>
public sealed class CompressionProcessor : DataProcessorBase
{
    private readonly CompressionLevel _level;

    /// <summary>创建压缩处理器。</summary>
    /// <param name="compressionLevel">.NET GZip 压缩预设。</param>
    public CompressionProcessor(CompressionLevel compressionLevel)
    {
        _level = compressionLevel;
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
