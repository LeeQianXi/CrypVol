using System.Buffers;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>从源文件读取数据块的数据提供者。</summary>
public sealed class SourceFileDataProvider : DataProviderBase
{
    private readonly IReadOnlyList<BlockMetadata> _blocks;
    private string? _openPath;
    private FileStream? _stream;

    /// <summary>创建源文件数据提供者。</summary>
    /// <param name="blocks">按读取顺序排列的数据块元数据。</param>
    public SourceFileDataProvider(IReadOnlyList<BlockMetadata> blocks)
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

        Engine.LogTrace("源文件数据提供完成: {BlockCount} 块", _blocks.Count);
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
        if (metadata.Length == 0)
            return new DataBlock(ArrayPool<byte>.Shared.Rent(0), 0, metadata);

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
            Engine.LogTrace("文件读: {Path}@{Offset:X} {Bytes}字节",
                metadata.RelativePath, metadata.SourceOffset, read);
            return new DataBlock(buffer, read, metadata);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buffer);
            throw;
        }
    }
}