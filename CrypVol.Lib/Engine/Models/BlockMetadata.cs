namespace CrypVol.Lib.Engine.Models;

/// <summary>
///     描述数据块的来源、顺序和目标。元数据只负责表达处理上下文，不持有数据缓冲区。
/// </summary>
public sealed class BlockMetadata
{
    /// <summary>文件相对路径</summary>
    public required string RelativePath { get; init; }

    /// <summary>源文件全路径</summary>
    public required string SourceFullPath { get; init; }

    /// <summary>目标编号；当前卷处理使用卷序号。</summary>
    public int TargetIndex { get; init; }

    /// <summary>卷内全局递增序号（从 0 起，跨文件连续）</summary>
    public long Sequence { get; init; }

    /// <summary>源文件读取偏移</summary>
    public long SourceOffset { get; init; }

    /// <summary>本次读取字节数</summary>
    public int Length { get; init; }

    /// <summary>文件总大小</summary>
    public long TotalFileSize { get; init; }

    /// <summary>段标志（Full/CrossHead/CrossMid/CrossTail）</summary>
    public byte Flags { get; init; }

    /// <summary>是否在该块前写入 FileEntryHeader。</summary>
    public bool IsFirstFragment { get; init; }
}
