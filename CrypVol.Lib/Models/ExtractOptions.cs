namespace CrypVol.Lib.Models;

public sealed record ExtractOptions
{
    /// <summary>.cvp 卷文件路径或所在目录</summary>
    public required IReadOnlyList<string> VolumePaths { get; init; }

    /// <summary>还原目标目录</summary>
    public required string OutputDir { get; init; }

    /// <summary>.cvk 密钥文件路径（自动搜索同目录）</summary>
    public string? KeyFilePath { get; init; }

    /// <summary>解密密码</summary>
    public string? Password { get; init; }

    /// <summary>私钥文件路径</summary>
    public string? PrivateKeyPath { get; init; }

    /// <summary>覆盖已存在文件</summary>
    public bool Overwrite { get; init; }

    /// <summary>并行线程数</summary>
    public int Threads { get; init; } = Environment.ProcessorCount;
}

public sealed record ExtractResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public int FileCount { get; init; }
    public long TotalBytes { get; init; }
}