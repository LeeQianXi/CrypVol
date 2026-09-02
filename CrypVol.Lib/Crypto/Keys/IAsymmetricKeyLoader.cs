namespace CrypVol.Lib.Crypto.Keys;

/// <summary>统一的公钥/私钥文件解析契约。</summary>
public interface IAsymmetricKeyLoader
{
    /// <summary>尝试解析公钥文件，成功返回 true。</summary>
    bool LoadPublicKey(FileInfo file, out AsymmetricPublicKeyMaterial key, string? keyId = null);

    /// <summary>尝试解析私钥文件，成功返回 true。</summary>
    bool LoadPrivateKey(FileInfo file, out AsymmetricPrivateKeyMaterial key, string? password = null, string? keyId = null);
}