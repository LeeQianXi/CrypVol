using System.Threading.Channels;

namespace CrypVol.Lib.Pipeline;

/// <summary>
///     单个输出卷的运行时上下文。
/// </summary>
public sealed class VolumeContext
{
    /// <summary>卷序号（从 0 开始）</summary>
    public int VolumeIndex { get; init; }

    /// <summary>输出文件路径</summary>
    public string OutputPath { get; set; } = string.Empty;

    /// <summary>预分配的卷文件大小（字节）</summary>
    public long PreallocatedSize { get; set; }

    /// <summary>有序输出通道。容量=1，与 Route 形成反压，防止 Write 延迟时内存积压。</summary>
    public Channel<ProcessedBlock> OutputChannel { get; } =
        Channel.CreateBounded<ProcessedBlock>(new BoundedChannelOptions(1)
        {
            SingleReader = true,
            SingleWriter = true
        });
}