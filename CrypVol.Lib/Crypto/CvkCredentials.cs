namespace CrypVol.Lib.Crypto;

/// <summary>进入处理引擎的轻量加密凭据，仅携带运行所需的模式与只读 CEK。</summary>
public sealed class CvkCredentials
{
    /// <summary>创建运行凭据，并复制 CEK 以隔离调用方的可变数组。</summary>
    /// <param name="encryptionMode">内容加密模式。</param>
    /// <param name="cek">内容加密密钥。</param>
    public CvkCredentials(EncryptionMode encryptionMode, ReadOnlyMemory<byte> cek)
    {
        EncryptionMode = encryptionMode;
        Cek = cek.ToArray();
    }

    /// <summary>内容加密模式。</summary>
    public EncryptionMode EncryptionMode { get; }

    /// <summary>内容加密密钥的只读视图。</summary>
    public ReadOnlyMemory<byte> Cek { get; }

    /// <summary>支持现有的模式/CEK 元组解构调用。</summary>
    public void Deconstruct(out EncryptionMode encryptionMode, out ReadOnlyMemory<byte> cek)
    {
        encryptionMode = EncryptionMode;
        cek = Cek;
    }
}
