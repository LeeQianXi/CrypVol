using System.Buffers;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>在最终存储的数据块后附加文件摘要和块级 CRC32。</summary>
public sealed class IntegrityAppendProcessor : DataProcessorBase
{
    private readonly IntegrityLevel _level;

    /// <summary>创建完整性附加处理器。</summary>
    /// <param name="level">要写入的完整性等级。</param>
    public IntegrityAppendProcessor(IntegrityLevel level)
    {
        _level = level;
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        var appendFileHash = _level >= IntegrityLevel.File && IsLastFileBlock(block.Metadata);
        var appendCrc = _level >= IntegrityLevel.Block;
        var length = block.Length + (appendFileHash ? 32 : 0) + (appendCrc ? sizeof(uint) : 0);
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        block.Data.CopyTo(buffer);
        var position = block.Length;

        if (appendFileHash)
        {
            var hash = block.Metadata.FileHash ?? throw new InvalidDataException("文件末块缺少 SHA-256 摘要。");
            if (hash.Length != 32) throw new InvalidDataException("文件 SHA-256 摘要长度无效。");
            hash.CopyTo(buffer, position);
            position += hash.Length;
        }

        if (appendCrc)
            BitConverter.GetBytes(Crc32.Compute(buffer.AsSpan(0, position))).CopyTo(buffer, position);

        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, length, block.Metadata));
    }

    /// <summary>判断数据块是否为一个文件的最后一个块。</summary>
    private static bool IsLastFileBlock(BlockMetadata metadata)
    {
        return (metadata.Flags & 3) is (byte)FileEntryHeaderFlagsEnum.Full or (byte)FileEntryHeaderFlagsEnum.CrossTail;
    }
}