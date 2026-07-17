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
    public int VolumeIndex { get; init; }

    /// <summary>
    ///     写入线程当前渴望的序号
    /// </summary>
    public long NextExpectedSeq { get; set; } = 0;

    public SortedDictionary<long, EncryptedBlock> Buffer { get; } = new();

    /// <summary>
    ///     专属数据通道
    /// </summary>
    public Channel<EncryptedBlock> OutputChannel { get; init; } = Channel.CreateBounded<EncryptedBlock>(32);

    public int TotalBlocks { get; set; }
    public int ReceivedCount { get; set; } = 0;
}