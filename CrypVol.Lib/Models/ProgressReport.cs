namespace CrypVol.Lib.Models;

/// <summary>进度报告</summary>
public sealed class ProgressReport
{
    /// <summary>当前阶段：Read / Transform / Write</summary>
    public string Phase { get; init; } = "";

    /// <summary>已处理项数</summary>
    public int Completed { get; init; }

    /// <summary>总项数（0 表示未知）</summary>
    public int Total { get; init; }

    /// <summary>当前文件路径或卷名</summary>
    public string? Detail { get; init; }
}