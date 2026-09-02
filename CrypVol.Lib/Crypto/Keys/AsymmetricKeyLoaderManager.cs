using CrypVol.Lib.Utility;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>管理公钥/私钥格式加载器，并按顺序尝试注入的实现。</summary>
public sealed class AsymmetricKeyLoaderManager : StaticSingleton<AsymmetricKeyLoaderManager>
{
    private readonly IReadOnlyList<IAsymmetricKeyLoader> _loaders =
    [
        OpenSshAsymmetricKeyLoader.Instance,
        PemAsymmetricKeyLoader.Instance
    ];

    /// <summary>尝试遍历加载器解析公钥。</summary>
    public bool LoadPublicKey(FileInfo file, out AsymmetricPublicKeyMaterial key, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在。", file.FullName);
        foreach (var loader in _loaders)
            if (loader.LoadPublicKey(file, out key, keyId))
                return true;
        key = null!;
        return false;
    }

    /// <summary>尝试遍历加载器解析私钥。</summary>
    public bool LoadPrivateKey(FileInfo file, out AsymmetricPrivateKeyMaterial key,
        string? password = null, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在。", file.FullName);
        foreach (var loader in _loaders)
            if (loader.LoadPrivateKey(file, out key, password, keyId))
                return true;
        key = null!;
        return false;
    }
}