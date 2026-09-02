using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Helper.Models;

public sealed record VerifyOptions
{
    /// <summary>.cvp 卷文件</summary>
    public required IReadOnlyCollection<FileInfo> VolumeFiles { get; init; }

    /// <summary>已加载的密钥</summary>
    public required CvkCredentials Credentials { get; init; }

    /// <summary>仅快速检查头结构（跳过 CRC32 数据校验）</summary>
    public bool Quick { get; init; }

    /// <summary>Glob 包含模式</summary>
    public string? IncludePattern { get; init; }

    /// <summary>Glob 排除模式</summary>
    public string? ExcludePattern { get; init; }
}

public sealed record VerifyResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public int TotalFiles { get; init; }
    public int TotalBlocks { get; init; }
    public int CorruptedFiles { get; init; }
    public int CorruptedBlocks { get; init; }
    public List<CorruptedBlock> CorruptedEntries { get; init; } = [];
}

public sealed record CorruptedBlock
{
    /// <summary>损坏数据块所在 CVP 卷的完整路径。</summary>
    public required string VolumePath { get; init; }

    public required string FilePath { get; init; }
    public long CvpOffset { get; init; }
    public int BlockSize { get; init; }
}