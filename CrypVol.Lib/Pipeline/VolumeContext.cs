using System.Threading.Channels;

namespace CrypVol.Lib.Pipeline;

/// <summary>
///     单个输出卷的运行时上下文。
/// </summary>
public sealed class VolumeContext
{
    /// <summary>卷序号（从 0 开始）</summary>
    public int VolumeIndex { get; init; }

    /// <summary>该卷包含的所有工作项（有序）</summary>
    public List<WorkItem> Items { get; } = [];

    /// <summary>输出文件路径</summary>
    public string OutputPath { get; set; } = string.Empty;

    /// <summary>预分配的卷文件大小（字节）</summary>
    public long PreallocatedSize { get; set; }

    /// <summary>有序输出通道（无界 — 卷间互不阻塞，内存由 processed channel 控制）</summary>
    public Channel<ProcessedBlock> OutputChannel { get; } =
        Channel.CreateUnbounded<ProcessedBlock>();
}