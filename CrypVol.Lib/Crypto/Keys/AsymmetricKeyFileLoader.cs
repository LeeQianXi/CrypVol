using System.Buffers.Binary;
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

        if (TryLoadOpenSshRsa(text, file, keyId, resolvedId, out var openSsh))
            return openSsh!;

        // EC 公钥的 SubjectPublicKeyInfo 编码无法区分 ECDSA 与 ECDH；
        // 对明确命名为 ECDH 的文件优先尝试 ECDH，其余保持 ECDSA 优先。
        var ecLoaders = IsEcdhHint(file, resolvedId)
            ? new Func<AsymmetricPublicKeyMaterial>[] { () => LoadEcdhPublic(text, resolvedId), () => LoadEcdsaPublic(text, resolvedId) }
            : new Func<AsymmetricPublicKeyMaterial>[] { () => LoadEcdsaPublic(text, resolvedId), () => LoadEcdhPublic(text, resolvedId) };

        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(text);
            return new AsymmetricPublicKeyMaterial(resolvedId, "RSA", rsa);
        }
        catch (Exception) { }

        foreach (var loader in ecLoaders)
        {
            try { return loader(); }
            catch (Exception) { }
        }

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

        var ecdhFirst = IsEcdhHint(file, resolvedId) || text.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal);
        Exception? last = null;
        foreach (var algorithm in ecdhFirst ? new[] { "ECDH", "ECDSA" } : new[] { "ECDSA", "ECDH" })
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

        throw new AsymmetricKeyFileFormatException($"无法加载私钥文件：{file.FullName}。请确认 PEM 格式和密码正确。", last);
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

    private static bool IsEcdhHint(FileInfo file, string keyId) =>
        file.Name.Contains("ecdh", StringComparison.OrdinalIgnoreCase) ||
        keyId.Contains("ecdh", StringComparison.OrdinalIgnoreCase);

    /// <summary>尝试读取单行 OpenSSH authorized_keys 格式的 RSA 公钥。</summary>
    private static bool TryLoadOpenSshRsa(string text, FileInfo file, string? explicitKeyId,
        string fallbackId, out AsymmetricPublicKeyMaterial? material)
    {
        material = null;
        var line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(static value => !value.StartsWith('#'));
        if (line is null) return false;
        var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !string.Equals(fields[0], "ssh-rsa", StringComparison.Ordinal)) return false;

        try
        {
            var blob = Convert.FromBase64String(fields[1]);
            var offset = 0;
            var type = ReadSshField(blob, ref offset);
            if (!type.SequenceEqual("ssh-rsa"u8)) throw new FormatException("OpenSSH RSA 类型字段无效。");
            var exponent = NormalizeMpint(ReadSshField(blob, ref offset));
            var modulus = NormalizeMpint(ReadSshField(blob, ref offset));
            if (offset != blob.Length || exponent.Length == 0 || modulus.Length == 0)
                throw new FormatException("OpenSSH RSA 公钥字段不完整。");

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Exponent = exponent, Modulus = modulus });
            var id = !string.IsNullOrWhiteSpace(explicitKeyId)
                ? explicitKeyId!
                : fields.Length >= 3 ? string.Join(' ', fields[2..]) : fallbackId;
            material = new AsymmetricPublicKeyMaterial(id, "RSA", rsa);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException or OverflowException)
        {
            throw new AsymmetricKeyFileFormatException($"无法识别 OpenSSH RSA 公钥文件：{file.FullName}", ex);
        }
    }

    private static ReadOnlySpan<byte> ReadSshField(ReadOnlySpan<byte> blob, ref int offset)
    {
        if (offset > blob.Length - 4) throw new FormatException("OpenSSH 字段长度缺失。");
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob[offset..]);
        offset += 4;
        if (length > int.MaxValue || offset > blob.Length - (int)length)
            throw new FormatException("OpenSSH 字段长度越界。");
        var field = blob.Slice(offset, (int)length);
        offset += (int)length;
        return field;
    }

    private static byte[] NormalizeMpint(ReadOnlySpan<byte> value)
    {
        while (value.Length > 1 && value[0] == 0) value = value[1..];
        return value.ToArray();
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
