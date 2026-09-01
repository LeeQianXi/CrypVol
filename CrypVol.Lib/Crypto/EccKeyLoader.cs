using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CrypVol.Lib.Crypto;

/// <summary>使用 P-256 ECDH 公私钥封装和解封 DEK。</summary>
public static class EccKeyLoader
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSize = 32;

    /// <summary>从 PEM 文本加载 P-256 公钥。</summary>
    public static ECDiffieHellman LoadPublicKey(string keyText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyText);
        var key = ECDiffieHellman.Create();
        try { key.ImportFromPem(keyText); EnsureP256(key); return key; }
        catch { key.Dispose(); throw new CryptographicException("不支持的 ECC 公钥格式；请提供 P-256 PEM 公钥。"); }
    }

    /// <summary>从 PEM 文本加载 P-256 私钥。</summary>
    public static ECDiffieHellman LoadPrivateKey(string keyText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyText);
        var key = ECDiffieHellman.Create();
        try { key.ImportFromPem(keyText); EnsureP256(key); return key; }
        catch { key.Dispose(); throw new CryptographicException("不支持的 ECC 私钥格式；请提供 P-256 PEM 私钥。"); }
    }

    /// <summary>使用临时 P-256 密钥和接收者公钥封装 DEK。</summary>
    public static byte[] WrapDek(ECDiffieHellman publicKey, ReadOnlySpan<byte> dek)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (dek.Length != DekSize) throw new ArgumentException("DEK 必须是 32 字节。", nameof(dek));
        EnsureP256(publicKey);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephemeralPublic = ephemeral.PublicKey.ExportSubjectPublicKeyInfo();
        var shared = ephemeral.DeriveKeyMaterial(publicKey.PublicKey);
        var key = SHA256.HashData(shared);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var ciphertext = new byte[DekSize];
        using (var aes = new AesGcm(key, TagSize)) aes.Encrypt(nonce, dek, ciphertext, tag);
        var result = new byte[sizeof(ushort) + ephemeralPublic.Length + NonceSize + TagSize + DekSize];
        BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)ephemeralPublic.Length));
        ephemeralPublic.CopyTo(result.AsSpan(sizeof(ushort)));
        var offset = sizeof(ushort) + ephemeralPublic.Length;
        nonce.CopyTo(result, offset); offset += NonceSize;
        tag.CopyTo(result, offset); offset += TagSize;
        ciphertext.CopyTo(result, offset);
        CryptographicOperations.ZeroMemory(shared); CryptographicOperations.ZeroMemory(key);
        return result;
    }

    /// <summary>使用接收者 P-256 私钥解封 DEK。</summary>
    public static byte[] UnwrapDek(ECDiffieHellman privateKey, ReadOnlySpan<byte> wrapped)
    {
        ArgumentNullException.ThrowIfNull(privateKey); EnsureP256(privateKey);
        if (wrapped.Length < sizeof(ushort) + 91 + NonceSize + TagSize + DekSize)
            throw new CryptographicException("ECC DEK 载荷长度不足。");
        var publicLength = BinaryPrimitives.ReadUInt16BigEndian(wrapped);
        var offset = sizeof(ushort);
        if (publicLength == 0 || offset + publicLength + NonceSize + TagSize + DekSize != wrapped.Length)
            throw new CryptographicException("ECC 临时公钥载荷长度无效。");
        using var ephemeral = ECDiffieHellman.Create();
        ephemeral.ImportSubjectPublicKeyInfo(wrapped.Slice(offset, publicLength), out _);
        offset += publicLength;
        var shared = privateKey.DeriveKeyMaterial(ephemeral.PublicKey);
        var key = SHA256.HashData(shared);
        var dek = new byte[DekSize];
        using (var aes = new AesGcm(key, TagSize))
            aes.Decrypt(wrapped.Slice(offset, NonceSize), wrapped.Slice(offset + NonceSize + TagSize, DekSize),
                wrapped.Slice(offset + NonceSize, TagSize), dek);
        CryptographicOperations.ZeroMemory(shared); CryptographicOperations.ZeroMemory(key);
        return dek;
    }

    private static void EnsureP256(ECDiffieHellman key)
    {
        var parameters = key.ExportParameters(false);
        if (!string.Equals(parameters.Curve.Oid.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal))
            throw new CryptographicException("仅支持 P-256 ECC 密钥。");
    }
}
