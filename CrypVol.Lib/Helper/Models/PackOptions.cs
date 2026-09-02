using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Helper.Models;

public sealed record PackOptions
{
    public required DirectoryInfo SourceFolder { get; init; }

    /// <summary>待处理源文件列表</summary>
    public required IReadOnlyCollection<FileInfo> SourceFiles { get; init; }

    /// <summary>输出目录</summary>
    public required DirectoryInfo OutputDir { get; init; }

    /// <summary>文件名前缀</summary>
    [field: AllowNull]
    public string OutputPrefix
    {
        get => field ?? SourceFolder.Name;
        init;
    }

    /// <summary>单卷近似切分目标（MiB）；处理后的块可能因压缩、加密或完整性数据略有偏差。</summary>
    public uint VolumeSizeMb { get; init; } = 1024;

    /// <summary>
    ///     单个数据块的最大原始大小（MiB）。该值决定流式读取粒度、压缩窗口和近似卷切分粒度。
    ///     有效范围为 1–64 MiB。
    /// </summary>
    public uint ChunkSizeMb { get; init; } = 16;

    /// <summary>已加载的 CEK 凭据（CLI 预加载后传入）</summary>
    public required CvkCredentials Credentials { get; init; }

    /// <summary>启用 GZip 压缩。</summary>
    public bool EnableCompression { get; init; } = true;

    /// <summary>.NET GZip 压缩预设。</summary>
    public CompressionLevel CompressionLevel { get; init; } = CompressionLevel.Optimal;

    /// <summary>完整性校验级别。</summary>
    public IntegrityLevel IntegrityLevel { get; init; } = IntegrityLevel.Block;
}

public sealed record PackResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> VolumePaths { get; init; } = [];
    public int VolumeCount { get; init; }
    public long TotalBytes { get; init; }
}