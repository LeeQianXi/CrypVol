using System.Security.Cryptography;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>已加载的非对称私钥材料。</summary>
public sealed class AsymmetricPrivateKeyMaterial : IDisposable
{
    internal AsymmetricPrivateKeyMaterial(string keyId, string algorithm, AsymmetricAlgorithm key)
    {
        KeyId = keyId;
        Algorithm = algorithm;
        Key = key;
        PublicKeyBytes = key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
            ECDiffieHellman ecdh => ecdh.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException($"不支持的私钥算法：{key.GetType().Name}")
        };
    }

    /// <summary>逻辑 KeyId。</summary>
    public string KeyId { get; }

    /// <summary>算法名称。</summary>
    public string Algorithm { get; }

    /// <summary>可执行私钥对象。</summary>
    public AsymmetricAlgorithm Key { get; }

    /// <summary>对应的 SubjectPublicKeyInfo 编码。</summary>
    public byte[] PublicKeyBytes { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        Key.Dispose();
    }
}