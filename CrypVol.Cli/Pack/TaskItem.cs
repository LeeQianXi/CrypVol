namespace CrypVol.Cli.Pack;

/// 描述一次“读取动作”的全部坐标
public readonly record struct TaskItem
{
    /// 相对路径或绝对路径
    public string FilePath { get; init; }

    /// 路径哈希（FNV-1a 64bit）
    public long FileId { get; init; }

    /// 目标卷号
    public int VolumeIndex { get; init; }

    /// 该卷内的全局递增序号（从 0 起）
    public long Sequence { get; init; }

    /// 在源文件中的读取起始偏移
    public long SourceOffset { get; init; }

    /// 本次读取的字节数（≤ 单块最大尺寸）
    public int Length { get; init; }

    /// 文件的完整总大小（用于头部）
    public long TotalFileSize { get; init; }
}