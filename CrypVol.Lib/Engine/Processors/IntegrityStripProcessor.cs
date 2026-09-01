using System.Buffers;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>校验并剥离存储块末尾的 CRC32 与文件 SHA-256 摘要。</summary>
public sealed class IntegrityStripProcessor : DataProcessorBase
{
    private readonly IntegrityLevel _level;

    /// <summary>创建完整性剥离处理器。</summary>
    /// <param name="level">卷头记录的完整性等级。</param>
    public IntegrityStripProcessor(IntegrityLevel level)
    {
        _level = level;
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        var length = block.Length;
        if (_level >= IntegrityLevel.Block)
        {
            if (length < sizeof(uint)) throw new InvalidDataException("数据块缺少 CRC32。");
            var crcOffset = length - sizeof(uint);
            var expected = BitConverter.ToUInt32(block.Buffer, crcOffset);
            var actual = Crc32.Compute(block.Buffer.AsSpan(0, crcOffset));
            if (expected != actual) throw new InvalidDataException($"CRC32 校验失败: 期望 {expected:X8}, 实际 {actual:X8}");
            length = crcOffset;
        }

        if (_level >= IntegrityLevel.File && IsLastFileBlock(block.Metadata))
        {
            if (length < 32) throw new InvalidDataException("文件末块缺少 SHA-256 摘要。");
            block.Metadata.FileHash = block.Buffer.AsSpan(length - 32, 32).ToArray();
            length -= 32;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(length);
        block.Buffer.AsSpan(0, length).CopyTo(buffer);
        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, length, block.Metadata));
    }

    /// <summary>判断数据块是否为一个文件的最后一个块。</summary>
    private static bool IsLastFileBlock(BlockMetadata metadata)
    {
        return (metadata.Flags & 3) is (byte)FileEntryHeaderFlagsEnum.Full or (byte)FileEntryHeaderFlagsEnum.CrossTail;
    }
}