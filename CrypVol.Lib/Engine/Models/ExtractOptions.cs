using CrypVol.Lib.Crypto;

namespace CrypVol.Lib.Engine.Models;

public sealed record ExtractOptions
{
    /// <summary>.cvp 卷文件（CLI 已解析为具体文件）</summary>
    public required IReadOnlyCollection<FileInfo> VolumeFiles { get; init; }

    /// <summary>还原目标目录</summary>
    public required DirectoryInfo OutputDir { get; init; }

    /// <summary>已加载的密钥（null = 未加密）</summary>
    public required CvkCredentials Credentials { get; init; }

    /// <summary>Glob 包含模式</summary>
    public string? IncludePattern { get; init; }

    /// <summary>Glob 排除模式</summary>
    public string? ExcludePattern { get; init; }

    public bool Overwrite { get; init; }
    public int Threads { get; init; } = Environment.ProcessorCount;
}

public sealed record ExtractResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public int FileCount { get; init; }
    public long TotalBytes { get; init; }
}