namespace CrypVol.Lib.Models;

public sealed record PackOptions
{
    /// <summary>源目录或文件路径</summary>
    public required string SourcePath { get; init; }

    /// <summary>输出目录</summary>
    public required string OutputDir { get; init; }

    /// <summary>文件名前缀</summary>
    public string OutputPrefix { get; init; } = "";

    /// <summary>单卷大小上限（MiB）</summary>
    public uint VolumeSizeMb { get; init; } = 1024;

    /// <summary>加密模式</summary>
    public EncryptionMode EncryptionMode { get; init; } = EncryptionMode.PlainKey;

    /// <summary>密码（Password 模式）</summary>
    public string? Password { get; init; }

    /// <summary>公钥文件列表（Asymmetric 模式）</summary>
    public IReadOnlyList<string>? PublicKeyPaths { get; init; }

    /// <summary>复用已有 .cvk（与 EncryptionMode/Password 互斥）</summary>
    public string? KeyFilePath { get; init; }

    /// <summary>已有 .cvk 的解密密码</summary>
    public string? KeyFilePassword { get; init; }

    /// <summary>已有 .cvk 的解密私钥路径（Asymmetric 模式）</summary>
    public string? PrivateKeyPath { get; init; }

    /// <summary>Glob 包含模式</summary>
    public string? IncludePattern { get; init; }

    /// <summary>Glob 排除模式</summary>
    public string? ExcludePattern { get; init; }

    /// <summary>启用 GZip 压缩</summary>
    public bool EnableCompression { get; init; }

    /// <summary>压缩级别 0-9</summary>
    public int CompressionLevel { get; init; } = 6;

    /// <summary>并行线程数</summary>
    public int Threads { get; init; } = Environment.ProcessorCount;

    /// <summary>完整性校验级别</summary>
    public IntegrityLevel IntegrityLevel { get; init; } = IntegrityLevel.File;

    /// <summary>.cvk 备注</summary>
    public string? Comment { get; init; }
}

public sealed record PackResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> VolumePaths { get; init; } = [];
    public string? KeyFilePath { get; init; }
    public int VolumeCount { get; init; }
    public long TotalBytes { get; init; }
}