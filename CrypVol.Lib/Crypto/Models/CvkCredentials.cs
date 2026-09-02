namespace CrypVol.Lib.Crypto.Models;

/// <summary>进入 Engine 的轻量运行凭据，仅携带已经解封的 CEK。</summary>
public sealed class CvkCredentials
{
    /// <summary>创建 CVK 运行凭据。</summary>
    public CvkCredentials(CvkKeyProtection keyProtection, ReadOnlyMemory<byte> cek,
        CvkKeyWrapAlgorithm keyWrapAlgorithm = CvkKeyWrapAlgorithm.None)
    {
        if (!Enum.IsDefined(keyProtection)) throw new ArgumentOutOfRangeException(nameof(keyProtection));
        if (!Enum.IsDefined(keyWrapAlgorithm)) throw new ArgumentOutOfRangeException(nameof(keyWrapAlgorithm));
        if (cek.Length != 32 && !(cek.Length == 0 && keyProtection == CvkKeyProtection.Plain && keyWrapAlgorithm == CvkKeyWrapAlgorithm.None))
            throw new ArgumentException("受保护 CEK 必须是 32 字节；仅 Plain/None 允许为空。", nameof(cek));
        var validRoute = keyProtection switch
        {
            CvkKeyProtection.Plain => keyWrapAlgorithm == CvkKeyWrapAlgorithm.None,
            CvkKeyProtection.Password => keyWrapAlgorithm is CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256 or CvkKeyWrapAlgorithm.PasswordArgon2Id,
            CvkKeyProtection.PublicKey => keyWrapAlgorithm is CvkKeyWrapAlgorithm.RsaOaepSha256 or CvkKeyWrapAlgorithm.RsaOaepSha384
                or CvkKeyWrapAlgorithm.RsaOaepSha512 or CvkKeyWrapAlgorithm.EcdhP256 or CvkKeyWrapAlgorithm.EcdhP384 or CvkKeyWrapAlgorithm.EcdhP521,
            _ => false
        };
        if (!validRoute) throw new ArgumentException("保护模式与封装算法不匹配或未定义。", nameof(keyWrapAlgorithm));
        KeyProtection = keyProtection;
        KeyWrapAlgorithm = keyWrapAlgorithm;
        Cek = cek.ToArray();
    }

    /// <summary>CVK 的保护模式。</summary>
    public CvkKeyProtection KeyProtection { get; }

    /// <summary>CVK 的封装算法。</summary>
    public CvkKeyWrapAlgorithm KeyWrapAlgorithm { get; }

    /// <summary>内容加密密钥的只读视图。</summary>
    public ReadOnlyMemory<byte> Cek { get; }
}
