using System.Diagnostics.CodeAnalysis;
using CrypVol.Lib.Crypto;

namespace CrypVol.Lib.Engine.Models;

public sealed record PackOptions
{
    public required DirectoryInfo SourceFolder { get; init; }

    /// <summary>待处理源文件列表</summary>
    public required IReadOnlyCollection<FileInfo> SourceFiles { get; init; }

    /// <summary>输出目录</summary>
    public required DirectoryInfo OutputDir { get; init; }

    /// <summary>.cvk 单独输出目录（null = 与 OutputDir 相同）</summary>
    [field: AllowNull]
    public DirectoryInfo KeyOutputDir
    {
        get => field ?? OutputDir;
        init;
    }

    /// <summary>文件名前缀</summary>
    [field: AllowNull]
    public string OutputPrefix
    {
        get => field ?? SourceFolder.Name;
        init;
    }

    /// <summary>单卷大小上限（MiB）</summary>
    public uint VolumeSizeMb { get; init; } = 1024;

    /// <summary>已加载的 CEK 凭据（CLI 预加载后传入）</summary>
    public required CvkCredentials Credentials { get; init; }

    /// <summary>启用 GZip 压缩</summary>
    public bool EnableCompression { get; init; }

    /// <summary>压缩级别 0-9</summary>
    public int CompressionLevel { get; init; } = 6;

    /// <summary>并行线程数</summary>
    public int Threads { get; init; } = Environment.ProcessorCount;

    /// <summary>完整性校验级别</summary>
    public IntegrityLevel IntegrityLevel { get; init; } = IntegrityLevel.File;
}

public sealed record PackResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> VolumePaths { get; init; } = [];
    public int VolumeCount { get; init; }
    public long TotalBytes { get; init; }
}