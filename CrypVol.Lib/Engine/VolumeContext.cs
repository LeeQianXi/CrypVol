using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine;

/// <summary>
///     单个输出卷的运行时上下文。
/// </summary>
public sealed class VolumeContext
{
    /// <summary>卷序号（从 0 开始）</summary>
    public int VolumeIndex { get; init; }

    /// <summary>输出文件路径</summary>
    public string OutputPath { get; init; } = string.Empty;

    /// <summary>有序输出通道。容量=1，与 Route 形成反压，防止 Write 延迟时内存积压。</summary>
    public Channel<DataBlock> OutputChannel { get; } =
        Channel.CreateBounded<DataBlock>(new BoundedChannelOptions(1)
        {
            SingleReader = true,
            SingleWriter = true
        });
}