using System.Threading.Channels;

namespace CrypVol.Cli.Pack;

/// <summary>
///     卷上下文
/// </summary>
public sealed class VolumeContext
{
    /// <summary>
    ///     卷序号
    /// </summary>
    public required int VolumeIndex { get; init; }

    /// <summary>
    ///     源分配列表
    /// </summary>
    public List<FileEntry> Entries { get; } = [];

    /// <summary>
    ///     写入线程当前渴需求的序号
    /// </summary>
    public long NextExpectedSeq { get; set; }

    /// <summary>
    ///     写入线程滑动窗口
    /// </summary>
    public SortedDictionary<long, EncryptedBlock> Buffer { get; } = new();

    /// <summary>
    ///     专属数据通道
    /// </summary>
    public Channel<EncryptedBlock> OutputChannel { get; } = Channel.CreateBounded<EncryptedBlock>(32);

    /// <summary>
    ///     数据总块数
    /// </summary>
    public long TotalBlocks { get; set; }
}