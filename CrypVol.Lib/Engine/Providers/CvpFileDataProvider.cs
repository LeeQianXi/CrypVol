using System.Buffers;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>从 CVP 卷文件读取数据块的数据提供者。</summary>
public sealed class CvpFileDataProvider : DataProviderBase
{
    private readonly BlockMetadata[] _blocks;
    private string? _openPath;
    private FileStream? _stream;

    /// <summary>创建 CVP 文件数据提供者。</summary>
    /// <param name="blocks">按读取顺序排列的数据块元数据。</param>
    public CvpFileDataProvider(IEnumerable<BlockMetadata> blocks)
    {
        _blocks = blocks?.ToArray() ?? throw new ArgumentNullException(nameof(blocks));
    }

    /// <inheritdoc />
    protected override Task OnValidateAsync(CancellationToken cancellationToken = default)
    {
        foreach (var block in _blocks)
        {
            if (string.IsNullOrWhiteSpace(block.SourceFullPath))
                throw new InvalidDataException("数据块缺少源文件路径。");
            if (block.SourceOffset < 0)
                throw new InvalidDataException($"数据块源偏移不能为负数: {block.SourceFullPath}");
            if (block.Length < 0)
                throw new InvalidDataException("数据块长度不能为负数。");

            var source = new FileInfo(block.SourceFullPath);
            if (!source.Exists)
                throw new FileNotFoundException("CVP 源文件不存在。", source.FullName);
            if (block.SourceOffset > source.Length || block.Length > source.Length - block.SourceOffset)
                throw new InvalidDataException(
                    $"数据块超出源文件范围: {block.SourceFullPath} offset={block.SourceOffset:X}, length={block.Length}");
        }

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

        Engine.LogDebug("CVP 数据提供完成: {BlockCount} 块", _blocks.Length);
    }

    /// <inheritdoc />
    protected override async Task OnDisposeAsync(CancellationToken cancellationToken = default)
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
            if (read != metadata.Length)
                throw new EndOfStreamException($"CVP 数据块读取不完整: {metadata.SourceFullPath} offset={metadata.SourceOffset:X}");
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