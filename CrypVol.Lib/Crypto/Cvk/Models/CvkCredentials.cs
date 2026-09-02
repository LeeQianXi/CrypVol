namespace CrypVol.Lib.Crypto;

/// <summary>进入处理引擎的轻量加密凭据，携带保护模式、算法与只读 CEK。</summary>
public sealed class CvkCredentials
{
    /// <summary>创建运行凭据，并复制 CEK 以隔离调用方的可变数组。</summary>
    /// <param name="encryptionMode">内容加密模式。</param>
    /// <param name="cek">内容加密密钥。</param>
    /// <param name="encryptionAlgorithm">内容密钥使用的算法。</param>
    public CvkCredentials(EncryptionMode encryptionMode, ReadOnlyMemory<byte> cek,
        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.AesGcm)
    {
        EncryptionMode = encryptionMode;
        EncryptionAlgorithm = encryptionAlgorithm;
        Cek = cek.ToArray();
    }

    /// <summary>内容加密模式。</summary>
    public EncryptionMode EncryptionMode { get; }

    /// <summary>内容加密算法。</summary>
    public EncryptionAlgorithm EncryptionAlgorithm { get; }

    /// <summary>内容加密密钥的只读视图。</summary>
    public ReadOnlyMemory<byte> Cek { get; }

    /// <summary>支持现有的模式/CEK 元组解构调用。</summary>
    public void Deconstruct(out EncryptionMode encryptionMode, out ReadOnlyMemory<byte> cek)
    {
        encryptionMode = EncryptionMode;
        cek = Cek;
    }

    /// <summary>支持包含算法的模式、算法、CEK 元组解构调用。</summary>
    public void Deconstruct(out EncryptionMode encryptionMode, out EncryptionAlgorithm encryptionAlgorithm,
        out ReadOnlyMemory<byte> cek)
    {
        encryptionMode = EncryptionMode;
        encryptionAlgorithm = EncryptionAlgorithm;
        cek = Cek;
    }
}
