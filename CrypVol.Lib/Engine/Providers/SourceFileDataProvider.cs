using System.Buffers;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>流式读取源文件，并按近似卷容量将固定大小数据块路由到输出卷。</summary>
public sealed class SourceFileDataProvider : DataProviderBase
{
    private const int LengthFieldSize = sizeof(int);
    private readonly IReadOnlyList<FileInfo> _files;
    private readonly DirectoryInfo _sourceDirectory;
    private readonly int _chunkSize;
    private readonly long _volumeCapacity;
    private readonly int _headerSize;
    private readonly IntegrityLevel _integrityLevel;
    private readonly bool _enableCompression;
    private int _currentVolume;
    private long _currentVolumeUsed;
    private long _currentSequence;

    /// <summary>创建流式源文件提供者。</summary>
    public SourceFileDataProvider(IEnumerable<FileInfo> files, DirectoryInfo sourceDirectory, int chunkSize,
        long volumeCapacity, int headerSize, IntegrityLevel integrityLevel, bool enableCompression)
    {
        _files = files?.OrderBy(file => file.FullName, StringComparer.Ordinal).ToArray()
            ?? throw new ArgumentNullException(nameof(files));
        _sourceDirectory = sourceDirectory ?? throw new ArgumentNullException(nameof(sourceDirectory));
        _chunkSize = chunkSize;
        _volumeCapacity = volumeCapacity;
        _headerSize = headerSize;
        _integrityLevel = integrityLevel;
        _enableCompression = enableCompression;
    }

    /// <inheritdoc />
    public override Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        if (_chunkSize <= 0) throw new InvalidOperationException("数据块大小必须大于零。");
        if (_headerSize <= 0 || _volumeCapacity <= _headerSize + LengthFieldSize)
            throw new InvalidOperationException("卷容量不足以容纳文件头和数据块长度字段。");
        if (_chunkSize > _volumeCapacity - _headerSize - LengthFieldSize)
            throw new InvalidOperationException("数据块大小必须小于单卷可用容量。");
        if (_files.Any(file => !file.Exists)) throw new FileNotFoundException("待打包的源文件不存在。");
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override async Task ProduceCoreAsync(CancellationToken cancellationToken = default)
    {
        foreach (var file in _files)
            await ProduceFileAsync(file, cancellationToken);
        Engine.LogTrace("源文件数据提供完成: {FileCount} 文件，最后卷 {VolumeIndex}", _files.Count, _currentVolume);
    }

    private async Task ProduceFileAsync(FileInfo file, CancellationToken cancellationToken)
    {
        var relativePath = Path.GetRelativePath(_sourceDirectory.FullName, file.FullName);
        if (System.Text.Encoding.UTF8.GetByteCount(relativePath) > 230)
            throw new InvalidOperationException($"文件相对路径超过 CVP 头限制: {relativePath}");

        if (file.Length == 0)
        {
            await WriteBlockAsync(ArrayPool<byte>.Shared.Rent(0), 0, file, relativePath, 0, true, true,
                cancellationToken);
            return;
        }

        await using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read,
            _chunkSize, FileOptions.SequentialScan);
        long offset = 0;
        var isFirstFileBlock = true;
        while (offset < file.Length)
        {
            var requested = (int)Math.Min(_chunkSize, file.Length - offset);
            var buffer = ArrayPool<byte>.Shared.Rent(requested);
            try
            {
                var read = await ReadAtLeastAsync(stream, buffer, requested, cancellationToken);
                if (read == 0) throw new EndOfStreamException($"读取源文件时遇到意外结尾: {file.FullName}");
                await WriteBlockAsync(buffer, read, file, relativePath, offset, isFirstFileBlock,
                    offset + read >= file.Length, cancellationToken);
                buffer = null!;
                offset += read;
                isFirstFileBlock = false;
            }
            finally
            {
                if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    private async Task WriteBlockAsync(byte[] buffer, int length, FileInfo file, string relativePath, long offset,
        bool isFirstFileBlock, bool isLastFileBlock, CancellationToken cancellationToken)
    {
        var startsVolumeEntry = true;
        var initialCost = LengthFieldSize + length + _headerSize;
        if (_currentVolumeUsed > 0 && _currentVolumeUsed + initialCost > _volumeCapacity)
        {
            _currentVolume++;
            _currentVolumeUsed = 0;
            _currentSequence = 0;
        }

        var fragmentFlags = isFirstFileBlock
            ? (isLastFileBlock ? FileEntryHeaderFlagsEnum.Full : FileEntryHeaderFlagsEnum.CrossHead)
            : (isLastFileBlock ? FileEntryHeaderFlagsEnum.CrossTail : FileEntryHeaderFlagsEnum.CrossMid);
        var flags = (byte)fragmentFlags;
        flags |= (byte)(((int)_integrityLevel & 3) << 3);
        if (_enableCompression) flags |= (byte)FileEntryHeaderFlagsEnum.Compressed;
        var metadata = new BlockMetadata
        {
            RelativePath = relativePath,
            SourceFullPath = file.FullName,
            TargetIndex = _currentVolume,
            Sequence = _currentSequence++,
            SourceOffset = offset,
            Length = length,
            TotalFileSize = file.Length,
            Flags = flags,
            IsFirstFragment = startsVolumeEntry
        };

        try
        {
            await WriteAsync(new DataBlock(buffer, length, metadata), cancellationToken);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buffer);
            throw;
        }

        _currentVolumeUsed += LengthFieldSize + length + _headerSize;
    }

    private static async Task<int> ReadAtLeastAsync(FileStream stream, byte[] buffer, int requested,
        CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < requested)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, requested - total), cancellationToken);
            if (read == 0) break;
            total += read;
        }

        return total;
    }
}
