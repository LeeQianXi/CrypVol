using System.Buffers;

namespace CrypVol.Cli.Pipeline;

/// <summary>
///     管线中的一条工作项，描述一个文件片段的读取目标。
/// </summary>
public sealed class WorkItem
{
    /// <summary>文件相对路径</summary>
    public required string RelativePath { get; init; }

    /// <summary>源文件全路径</summary>
    public required string SourceFullPath { get; init; }

    /// <summary>目标卷号</summary>
    public int VolumeIndex { get; init; }

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

    /// <summary>是否为某文件的首个段（决定是否写 FileEntryHeader）</summary>
    public bool IsFirstFragment { get; init; }
}

/// <summary>
///     管线中流转的原始数据块（读阶段产出，变换阶段消费）。
/// </summary>
public sealed class RawBlock : IDisposable
{
    public required WorkItem Work { get; init; }

    /// <summary>ArrayPool 租借的缓冲区</summary>
    public required byte[] Data { get; init; }

    /// <summary>Data 中实际有效长度</summary>
    public int DataLength { get; init; }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(Data);
    }
}

/// <summary>
///     管线中流转的处理后数据块（变换阶段产出，路由阶段消费）。
///     总长度 = 变换后密文/压缩数据长度。
/// </summary>
public sealed class ProcessedBlock : IDisposable
{
    public required WorkItem Work { get; init; }

    /// <summary>ArrayPool 租借的缓冲区（含 nonce + ciphertext + tag 等变换后完整数据）</summary>
    public required byte[] Data { get; init; }

    /// <summary>变换后有效数据长度（写入卷时使用此值，而非 WorkItem.Length）</summary>
    public int OutputLength { get; init; }

    /// <summary>变换前原始数据长度（用于 FileEntryHeader.SizeOrTotal）</summary>
    public int OriginalLength { get; init; }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(Data);
    }
}
