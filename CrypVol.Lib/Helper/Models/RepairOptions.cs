using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Helper.Models;

public sealed record RepairOptions
{
    /// <summary>.cvp 卷文件</summary>
    public required IReadOnlyCollection<FileInfo> VolumeFiles { get; init; }

    /// <summary>已加载的密钥</summary>
    public required CvkCredentials Credentials { get; init; }

    /// <summary>输出目录（未指定时在原位置修复）</summary>
    public DirectoryInfo? OutputDir { get; init; }

    /// <summary>修复前创建 .bak 备份</summary>
    public bool Backup { get; init; }

    /// <summary>从 verify 报告读取损坏位置（跳过扫描）</summary>
    public FileInfo? VerifyReport { get; init; }
}

public sealed record RepairResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public int TotalBlocks { get; init; }
    public int RepairedBlocks { get; init; }
    public List<string> RepairedVolumes { get; init; } = [];
}