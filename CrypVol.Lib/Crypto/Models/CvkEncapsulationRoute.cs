namespace CrypVol.Lib.Crypto.Models;

/// <summary>
///     CVK 的封装路由。<see cref="CvkKeyProtection" /> 是封装级别，
///     <see cref="CvkKeyWrapAlgorithm" /> 只能选择该级别内部的实现，二者不可交叉组合。
/// </summary>
public sealed class CvkEncapsulationRoute
{
    private CvkEncapsulationRoute(CvkKeyProtection level, CvkKeyWrapAlgorithm algorithm)
    {
        Level = level;
        Algorithm = algorithm;
    }

    /// <summary>封装级别。</summary>
    public CvkKeyProtection Level { get; }

    /// <summary>级别内部使用的封装算法。</summary>
    public CvkKeyWrapAlgorithm Algorithm { get; }

    /// <summary>此路由是否需要密码。</summary>
    public bool RequiresPassword => Level == CvkKeyProtection.Password;

    /// <summary>此路由是否需要非对称接收者。</summary>
    public bool RequiresRecipients => Level == CvkKeyProtection.PublicKey;

    /// <summary>解析并校验一个封装路由。</summary>
    public static CvkEncapsulationRoute Resolve(CvkKeyProtection level, CvkKeyWrapAlgorithm algorithm)
    {
        if (!Enum.IsDefined(level)) throw new ArgumentOutOfRangeException(nameof(level));
        if (!Enum.IsDefined(algorithm)) throw new ArgumentOutOfRangeException(nameof(algorithm));

        var valid = level switch
        {
            CvkKeyProtection.Plain => algorithm == CvkKeyWrapAlgorithm.None,
            CvkKeyProtection.Password => algorithm is CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256
                or CvkKeyWrapAlgorithm.PasswordArgon2Id,
            CvkKeyProtection.PublicKey => algorithm is CvkKeyWrapAlgorithm.RsaOaepSha256
                or CvkKeyWrapAlgorithm.RsaOaepSha384
                or CvkKeyWrapAlgorithm.RsaOaepSha512
                or CvkKeyWrapAlgorithm.EcdhP256
                or CvkKeyWrapAlgorithm.EcdhP384
                or CvkKeyWrapAlgorithm.EcdhP521,
            _ => false
        };
        if (!valid)
            throw new ArgumentException($"封装级别与封装算法不匹配：{level}/{algorithm}。", nameof(algorithm));
        return new CvkEncapsulationRoute(level, algorithm);
    }
}