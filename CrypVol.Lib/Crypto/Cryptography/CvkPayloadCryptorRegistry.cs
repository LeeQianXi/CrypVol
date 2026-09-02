using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>按 CVK 保护模式和封装算法管理密钥体实现。</summary>
public sealed class CvkPayloadCryptorRegistry
{
    private readonly Dictionary<(CvkKeyProtection Protection, CvkKeyWrapAlgorithm Wrap), ICvkPayloadCryptor> _items = [];

    /// <summary>创建默认注册表。</summary>
    /// <remarks>只注册已经具备完整双向实现的算法；未实现算法不会伪装成可用。</remarks>
    public static CvkPayloadCryptorRegistry CreateDefault()
    {
        return new CvkPayloadCryptorRegistry()
            .Register(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, new PlainCvkPayloadCryptor())
            .Register(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256, new RsaOaepSha256Cryptor())
            .Register(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha384, new RsaOaepSha384Cryptor())
            .Register(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha512, new RsaOaepSha512Cryptor())
            .Register(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP256, new EcdhP256Cryptor())
            .Register(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP384, new EcdhP384Cryptor())
            .Register(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP521, new EcdhP521Cryptor());
    }

    /// <summary>创建默认注册表并注册指定密码对应的密码算法。</summary>
    public static CvkPayloadCryptorRegistry CreateDefault(string password)
    {
        var registry = CreateDefault();
        registry.Register(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256,
            new PasswordPbkdf2Sha256Cryptor(password));
        registry.Register(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id,
            new PasswordArgon2IdCryptor(password));
        return registry;
    }

    /// <summary>注册一个算法实现。</summary>
    public CvkPayloadCryptorRegistry Register(CvkKeyProtection protection,
        CvkKeyWrapAlgorithm wrapAlgorithm, ICvkPayloadCryptor cryptor)
    {
        ArgumentNullException.ThrowIfNull(cryptor);
        CvkEncapsulationRoute.Resolve(protection, wrapAlgorithm);
        _items[(protection, wrapAlgorithm)] = cryptor;
        return this;
    }

    /// <summary>解析 Header 对应的实现。</summary>
    public ICvkPayloadCryptor Resolve(CvkHeader header)
    {
        if (_items.TryGetValue((header.KeyProtection, header.KeyWrapAlgorithm), out var cryptor))
            return cryptor;
        throw new NotSupportedException(
            $"未注册 CVK 密钥体实现：保护模式={header.KeyProtection}，封装算法={header.KeyWrapAlgorithm}。");
    }
}