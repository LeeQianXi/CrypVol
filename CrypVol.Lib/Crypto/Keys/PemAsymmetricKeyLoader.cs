using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CrypVol.Lib.Utility;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>加载 PEM/PKCS#8 公钥、未加密私钥和带密码私钥文件。</summary>
/// <remarks>该加载器只处理 PEM 密钥格式，不读取 CVK 或 OpenSSH 文件。</remarks>
public sealed class PemAsymmetricKeyLoader : StaticSingleton<PemAsymmetricKeyLoader>, IAsymmetricKeyLoader
{
    /// <inheritdoc />
    public bool LoadPublicKey(FileInfo file, out AsymmetricPublicKeyMaterial key, string? keyId = null)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(file);
            var text = Read(file);
            if (!text.Contains("BEGIN", StringComparison.Ordinal) || text.Contains("OPENSSH", StringComparison.Ordinal))
            {
                key = null!;
                return false;
            }

            key = LoadPublicKeyCore(file, text, keyId);
            return true;
        }
        catch (FileNotFoundException) { throw; }
        catch (DirectoryNotFoundException) { throw; }
        catch (ArgumentNullException) { throw; }
        catch
        {
            key = null!;
            return false;
        }
    }

    /// <inheritdoc />
    public bool LoadPrivateKey(FileInfo file, out AsymmetricPrivateKeyMaterial key, string? password = null,
        string? keyId = null)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(file);
            var text = Read(file);
            if (!text.Contains("BEGIN", StringComparison.Ordinal) || text.Contains("OPENSSH", StringComparison.Ordinal))
            {
                key = null!;
                return false;
            }

            key = LoadPrivateKeyCore(file, text, password, keyId);
            return true;
        }
        catch (FileNotFoundException) { throw; }
        catch (DirectoryNotFoundException) { throw; }
        catch (ArgumentNullException) { throw; }
        catch
        {
            key = null!;
            return false;
        }
    }

    private static AsymmetricPublicKeyMaterial LoadPublicKeyCore(FileInfo file, string text, string? keyId)
    {
        if (text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new AsymmetricKeyFileFormatException($"公钥加载器拒绝私钥文件：{file.FullName}");
        var resolvedId = ResolveKeyId(file, keyId);

        var ecLoaders = IsEcdhHint(file, resolvedId)
            ? new[]
            {
                () => LoadEcdhPublic(text, resolvedId), () => LoadEcdsaPublic(text, resolvedId)
            }
            : new[]
            {
                () => LoadEcdsaPublic(text, resolvedId), () => LoadEcdhPublic(text, resolvedId)
            };
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(text);
            return new AsymmetricPublicKeyMaterial(resolvedId, "RSA", rsa);
        }
        catch (Exception) { }

        foreach (var loader in ecLoaders)
            try { return loader(); }
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

        throw new AsymmetricKeyFileFormatException($"无法识别 PEM 公钥文件：{file.FullName}");
    }

    private static AsymmetricPrivateKeyMaterial LoadPrivateKeyCore(FileInfo file, string text, string? password,
        string? keyId)
    {
        if (text.Contains("PUBLIC KEY", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new AsymmetricKeyFileFormatException($"私钥加载器拒绝公钥文件：{file.FullName}");
        var resolvedId = ResolveKeyId(file, keyId);
        var rsa = RSA.Create();
        try
        {
            Import(rsa, text, password);
            return new AsymmetricPrivateKeyMaterial(resolvedId, "RSA", rsa);
        }
        catch (Exception) { rsa.Dispose(); }

        Exception? last = null;
        var ecdhFirst = IsEcdhHint(file, resolvedId) || text.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal);
        foreach (var algorithm in ecdhFirst
                     ? new[]
                     {
                         "ECDH", "ECDSA"
                     }
                     : new[]
                     {
                         "ECDSA", "ECDH"
                     })
        {
            AsymmetricAlgorithm key = algorithm == "ECDH" ? ECDiffieHellman.Create() : ECDsa.Create();
            try
            {
                Import(key, text, password);
                return new AsymmetricPrivateKeyMaterial(resolvedId, algorithm, key);
            }
            catch (Exception ex)
            {
                last = ex;
                key.Dispose();
            }
        }

        throw new AsymmetricKeyFileFormatException($"无法加载 PEM 私钥文件：{file.FullName}。请确认 PEM 格式和密码正确。", last);
    }

    private static AsymmetricPublicKeyMaterial LoadEcdsaPublic(string text, string keyId)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(text);
        return new AsymmetricPublicKeyMaterial(keyId, "ECDSA", key);
    }

    private static AsymmetricPublicKeyMaterial LoadEcdhPublic(string text, string keyId)
    {
        var key = ECDiffieHellman.Create();
        key.ImportFromPem(text);
        return new AsymmetricPublicKeyMaterial(keyId, "ECDH", key);
    }

    private static bool IsEcdhHint(FileInfo file, string keyId)
    {
        return file.Name.Contains("ecdh", StringComparison.OrdinalIgnoreCase) ||
               keyId.Contains("ecdh", StringComparison.OrdinalIgnoreCase);
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