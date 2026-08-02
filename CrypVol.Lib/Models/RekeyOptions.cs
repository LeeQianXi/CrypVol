namespace CrypVol.Lib.Models;

public sealed record RekeyOptions
{
    /// <summary>源 .cvk 路径</summary>
    public required string SourceCvkPath { get; init; }

    /// <summary>目标 .cvk 路径（null = 覆盖源）</summary>
    public string? OutputPath { get; init; }

    /// <summary>目标保护模式</summary>
    public required EncryptionMode TargetMode { get; init; }

    /// <summary>源 .cvk 的解密密码</summary>
    public string? SourcePassword { get; init; }

    /// <summary>新密码（Password 模式）</summary>
    public string? NewPassword { get; init; }

    /// <summary>新公钥文件列表（Asymmetric 模式）</summary>
    public IReadOnlyList<string>? PublicKeyPaths { get; init; }

    /// <summary>源 .cvk 的解密私钥</summary>
    public string? SourcePrivateKeyPath { get; init; }

    /// <summary>操作前备份</summary>
    public bool Backup { get; init; }
}

public sealed record RekeyResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public string OutputPath { get; init; } = "";
}