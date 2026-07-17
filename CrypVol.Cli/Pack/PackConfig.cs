using CrypVol.Lib;

namespace CrypVol.Cli.Pack;

public sealed record PackConfig
{
    public string SourceDir { get; set; } = string.Empty;
    public IEnumerable<FileInfo> Files { get; set; } = [];
    public string OutputDir { get; set; } = string.Empty;
    public string KeyOutputDir { get; set; } = string.Empty;
    public string OutputPrefix { get; set; } = string.Empty;
    public long VolumeDataCapacity { get; set; } = 1L * 1024 * 1024 * 1024; // 1GB
    public int ComputeThreads { get; set; } = Environment.ProcessorCount;
    public bool EnableCompression { get; set; }
    public EncryptionMode Mode { get; set; } = EncryptionMode.PlainKey;
    public byte[] Cek { get; set; } = null!;
    public byte[] Salt { get; set; } = null!;
    public string Password { get; set; } = string.Empty;
    public IEnumerable<FileInfo> PublicKey { get; set; } = null!;
}