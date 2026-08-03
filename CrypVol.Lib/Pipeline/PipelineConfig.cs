namespace CrypVol.Lib.Pipeline;

/// <summary>
///     流水线运行时配置。
/// </summary>
public sealed record PipelineConfig
{
    /// <summary>读并发数（默认 4）</summary>
    public int ReaderConcurrency { get; init; } = 4;

    /// <summary>变换并发数（默认 = CPU 核心数）</summary>
    public int TransformConcurrency { get; init; } = Environment.ProcessorCount;

    /// <summary>写并发数上限（默认 2，避免磁盘争用）</summary>
    public int WriterConcurrency { get; init; } = 2;

    /// <summary>RawBlock 通道容量（默认 128）</summary>
    public int RawChannelCapacity { get; init; } = 128;

    /// <summary>ProcessedBlock 通道容量（默认 128，变换→路由的背压点）</summary>
    public int ProcessedChannelCapacity { get; init; } = 128;

    /// <summary>数据块对齐大小（字节）</summary>
    public int BlockSize { get; init; } = 4096;

    /// <summary>日志回调</summary>
    public Action<string>? LogInfo { get; init; }

    public Action<string>? LogVerbose { get; init; }
}