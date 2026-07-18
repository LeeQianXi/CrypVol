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

    public List<FileEntry> Entries { get; } = [];

    /// <summary>
    ///     写入线程当前渴望的序号
    /// </summary>
    public long NextExpectedSeq { get; set; }

    public SortedDictionary<long, EncryptedBlock> Buffer { get; } = new();

    /// <summary>
    ///     专属数据通道
    /// </summary>
    public Channel<EncryptedBlock> OutputChannel { get; } = Channel.CreateBounded<EncryptedBlock>(32);

    public long TotalBlocks { get; set; }
}