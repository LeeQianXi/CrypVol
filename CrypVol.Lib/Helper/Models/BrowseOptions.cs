using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Helper.Models;

public sealed record BrowseOptions
{
    /// <summary>.cvp 卷文件（CLI 已解析）</summary>
    public required IReadOnlyCollection<FileInfo> VolumeFiles { get; init; }

    /// <summary>已加载的密钥（None 哨兵 = 无密钥）</summary>
    public required CvkCredentials Credentials { get; init; }

    /// <summary>Glob 包含模式</summary>
    public string? IncludePattern { get; init; }

    /// <summary>Glob 排除模式</summary>
    public string? ExcludePattern { get; init; }
}

public sealed record BrowseResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public List<BrowseFileEntry> Files { get; init; } = [];
    public int VolumeCount { get; init; }
}

public sealed record BrowseFileEntry
{
    public required string Path { get; init; }
    public long Size { get; init; }
    public int FragmentCount { get; init; }
    public List<int> Volumes { get; init; } = [];
    public bool IsComplete { get; init; } = true;
}