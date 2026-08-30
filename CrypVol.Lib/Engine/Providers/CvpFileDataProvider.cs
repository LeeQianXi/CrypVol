using System.Buffers;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>从 CVP 卷文件读取数据块的数据提供者。</summary>
public sealed class CvpFileDataProvider : DataProviderBase
{
    private readonly IReadOnlyList<BlockMetadata> _blocks;
    private string? _openPath;
    private FileStream? _stream;

    /// <summary>创建 CVP 文件数据提供者。</summary>
    /// <param name="blocks">按读取顺序排列的数据块元数据。</param>
    public CvpFileDataProvider(IReadOnlyList<BlockMetadata> blocks)
    {
        _blocks = blocks ?? throw new ArgumentNullException(nameof(blocks));
    }

    /// <inheritdoc />
    public override Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        if (_blocks.Any(block => block.Length < 0))
            throw new InvalidOperationException("数据块长度不能为负数。");
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override async Task ProduceCoreAsync(CancellationToken cancellationToken = default)
    {
        foreach (var metadata in _blocks)
        {
            var block = await ReadAsync(metadata, cancellationToken);
            try
            {
                await WriteAsync(block, cancellationToken);
            }
            catch
            {
                block.Dispose();
                throw;
            }
        }

        Engine.LogTrace("CVP 数据提供完成: {BlockCount} 块", _blocks.Count);
    }

    /// <inheritdoc />
    public override async Task DisposeAsync(CancellationToken cancellationToken = default)
    {
        if (_stream is not null) await _stream.DisposeAsync();
        _stream = null;
        _openPath = null;
    }

    private async Task<DataBlock> ReadAsync(BlockMetadata metadata, CancellationToken cancellationToken)
    {
        if (metadata.SourceFullPath != _openPath)
        {
            if (_stream is not null) await _stream.DisposeAsync();
            _stream = File.OpenRead(metadata.SourceFullPath);
            _openPath = metadata.SourceFullPath;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(metadata.Length);
        try
        {
            _stream!.Position = metadata.SourceOffset;
            var read = await _stream.ReadAsync(buffer.AsMemory(0, metadata.Length), cancellationToken);
            Engine.LogTrace("CVP读: {Path}#{Sequence} offset={Offset:X} {Bytes}字节",
                metadata.RelativePath, metadata.Sequence, metadata.SourceOffset, read);
            return new DataBlock(buffer, read, metadata);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buffer);
            throw;
        }
    }
}