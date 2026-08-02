using CrypVol.Lib;

namespace CrypVol.Cli.Pack;

public sealed record PackConfig
{
    // ── 源与目标 ──
    /// <summary>源目录根路径</summary>
    public string SourceDir { get; set; } = string.Empty;

    /// <summary>待打包的文件列表</summary>
    public IEnumerable<FileInfo> Files { get; set; } = [];

    /// <summary>卷文件输出目录</summary>
    public string OutputDir { get; set; } = string.Empty;

    /// <summary>.cvk 密钥文件输出目录</summary>
    public string KeyOutputDir { get; set; } = string.Empty;

    /// <summary>输出文件前缀（卷名格式：&lt;前缀&gt;.&lt;卷号&gt;.cvp）</summary>
    public string OutputPrefix { get; set; } = string.Empty;

    // ── 卷参数 ──
    /// <summary>单卷数据容量上限（字节）</summary>
    public long VolumeDataCapacity { get; set; } = 1L * 1024 * 1024 * 1024; // 1 GiB

    // ── 压缩 ──
    /// <summary>是否启用 GZip 压缩</summary>
    public bool EnableCompression { get; set; }

    /// <summary>GZip 压缩级别 0-9（0=仅存储，9=最高压缩）</summary>
    public int CompressionLevel { get; set; } = 6;

    // ── 加密 ──
    /// <summary>密钥保护模式</summary>
    public EncryptionMode Mode { get; set; } = EncryptionMode.PlainKey;

    /// <summary>内容加密密钥（CEK，32 字节）</summary>
    public byte[] Cek { get; set; } = null!;

    /// <summary>密钥派生盐值（32 字节）</summary>
    public byte[] Salt { get; set; } = null!;

    /// <summary>密码（Password 模式）</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>接收者公钥文件列表（Asymmetric 模式）</summary>
    public IEnumerable<FileInfo> PublicKey { get; set; } = null!;

    // ── 完整性 ──
    /// <summary>数据完整性校验级别</summary>
    public IntegrityLevel IntegrityLevel { get; set; } = IntegrityLevel.File;

    // ── 并行度 ──
    /// <summary>压缩/加密并行线程数</summary>
    public int ComputeThreads { get; set; } = Environment.ProcessorCount;

    // ── 杂项 ──
    /// <summary>仅预估输出，不实际写入</summary>
    public bool DryRun { get; set; }

    /// <summary>嵌入 .cvk 的备注信息</summary>
    public string Comment { get; set; } = string.Empty;
}