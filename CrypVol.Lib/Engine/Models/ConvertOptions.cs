using CrypVol.Lib.Crypto;

namespace CrypVol.Lib.Engine.Models;

public sealed record ConvertOptions
{
    /// <summary>.cvp 卷文件（CLI 已解析）</summary>
    public required IReadOnlyCollection<FileInfo> VolumeFiles { get; init; }

    /// <summary>输出目录</summary>
    public required DirectoryInfo OutputDir { get; init; }

    /// <summary>输出文件名前缀</summary>
    public required string OutputPrefix { get; init; }

    /// <summary>旧 CEK（用于解密旧卷）</summary>
    public required CvkCredentials OldCredentials { get; init; }

    /// <summary>新 CEK（用于加密新卷）</summary>
    public required CvkCredentials NewCredentials { get; init; }
}

public sealed record ConvertResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> VolumePaths { get; init; } = [];
    public int VolumeCount { get; init; }
}