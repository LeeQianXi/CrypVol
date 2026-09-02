using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>加载通用非对称公钥、未加密私钥和带密码私钥文件。</summary>
/// <remarks>该类不读取 CVK 文件；CVK 文件应由独立的 CVK Loader 负责。</remarks>
public static class AsymmetricKeyFileLoader
{
    /// <summary>加载公钥文件。</summary>
    public static AsymmetricPublicKeyMaterial LoadPublicKey(FileInfo file, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        var text = Read(file);
        if (text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new AsymmetricKeyFileFormatException($"公钥加载器拒绝私钥文件：{file.FullName}");
        var resolvedId = ResolveKeyId(file, keyId);

        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(text);
            return new AsymmetricPublicKeyMaterial(resolvedId, "RSA", rsa);
        }
        catch (Exception) { }

        try
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(text);
            return new AsymmetricPublicKeyMaterial(resolvedId, "ECDSA", ecdsa);
        }
        catch (Exception) { }

        try
        {
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportFromPem(text);
            return new AsymmetricPublicKeyMaterial(resolvedId, "ECDH", ecdh);
        }
        catch (Exception) { }

        try
        {
            using var certificate = X509Certificate2.CreateFromPem(text);
            var rsa = certificate.GetRSAPublicKey();
            if (rsa is not null) return new AsymmetricPublicKeyMaterial(resolvedId, "RSA", rsa);
            var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is not null) return new AsymmetricPublicKeyMaterial(resolvedId, "ECDSA", ecdsa);
        }
        catch (Exception) { }

        throw new AsymmetricKeyFileFormatException($"无法识别公钥文件：{file.FullName}");
    }

    /// <summary>加载不带密码或带密码的私钥文件。</summary>
    public static AsymmetricPrivateKeyMaterial LoadPrivateKey(FileInfo file, string? password = null, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        var text = Read(file);
        var resolvedId = ResolveKeyId(file, keyId);

        var rsa = RSA.Create();
        try
        {
            Import(rsa, text, password);
            return new AsymmetricPrivateKeyMaterial(resolvedId, "RSA", rsa);
        }
        catch (Exception) { rsa.Dispose(); }

        var ecdsa = ECDsa.Create();
        try
        {
            Import(ecdsa, text, password);
            return new AsymmetricPrivateKeyMaterial(resolvedId, "ECDSA", ecdsa);
        }
        catch (Exception) { ecdsa.Dispose(); }

        var ecdh = ECDiffieHellman.Create();
        try
        {
            Import(ecdh, text, password);
            return new AsymmetricPrivateKeyMaterial(resolvedId, "ECDH", ecdh);
        }
        catch (Exception ex)
        {
            ecdh.Dispose();
            throw new AsymmetricKeyFileFormatException($"无法加载私钥文件：{file.FullName}。请确认 PEM 格式和密码正确。", ex);
        }
    }

    private static void Import(AsymmetricAlgorithm key, string text, string? password)
    {
        if (password is null)
        {
            key.ImportFromPem(text);
            return;
        }

        if (key is RSA rsa) rsa.ImportFromEncryptedPem(text, password);
        else if (key is ECDsa ecdsa) ecdsa.ImportFromEncryptedPem(text, password);
        else if (key is ECDiffieHellman ecdh) ecdh.ImportFromEncryptedPem(text, password);
        else throw new NotSupportedException();
    }

    private static string Read(FileInfo file)
    {
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在。", file.FullName);
        return File.ReadAllText(file.FullName);
    }

    private static string ResolveKeyId(FileInfo file, string? keyId)
    {
        return string.IsNullOrWhiteSpace(keyId) ? Path.GetFileNameWithoutExtension(file.Name) : keyId;
    }
}